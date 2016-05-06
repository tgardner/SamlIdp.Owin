namespace SamlIdp.Owin
{
    using System;
    using System.Globalization;
    using System.IdentityModel.Metadata;
    using System.IdentityModel.Tokens;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using System.Xml;
    using System.Xml.Linq;
    using global::Owin;
    using Kentor.AuthServices;
    using Kentor.AuthServices.Metadata;
    using Kentor.AuthServices.Saml2P;
    using Kentor.AuthServices.WebSso;
    using Microsoft.Owin;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.DataProtection;

    public class SamlIdpMiddleware : OwinMiddleware
    {
        private const string CookieName = "SamlIdp.Owin";

        private const string ResponseFormatString =
            @"<SOAP-ENV:Envelope
    xmlns:SOAP-ENV=""http://schemas.xmlsoap.org/soap/envelope/"">
    <SOAP-ENV:Body>
        <samlp:ArtifactResponse
            xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol""
            xmlns=""urn:oasis:names:tc:SAML:2.0:assertion""
            ID=""{0}"" Version=""2.0""
            InResponseTo = ""{1}""
            IssueInstant = ""{2}"">
            <Issuer>{4}</Issuer>
            <samlp:Status>
                <samlp:StatusCode Value = ""urn:oasis:names:tc:SAML:2.0:status:Success"" />
            </samlp:Status>
            {3}
        </samlp:ArtifactResponse>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>";

        protected static readonly PathString AuthorizePath = new PathString("/authorize");
        protected static readonly PathString MetadataPath = new PathString("/metadata");
        protected static readonly PathString ArtifactPath = new PathString("/artifact");
        protected static readonly PathString LogoutPath = new PathString("/logout");
        protected static readonly PathString CallbackPath = new PathString("");
        private readonly SamlIdpOptions _options;

        public SamlIdpMiddleware(OwinMiddleware next, IAppBuilder app, SamlIdpOptions options)
            : base(next)
        {
            options.DataProtector = app.CreateDataProtector(typeof (SamlIdpMiddleware).FullName);
            _options = options;
        }

        protected SamlIdpOptions Options
        {
            get { return _options; }
        }

        public override async Task Invoke(IOwinContext context)
        {
            if (context.Request.Path.Equals(AuthorizePath))
            {
                await CreateChallengeResponse(context);
                return;
            }

            if (context.Request.Path.Equals(CallbackPath))
            {
                CreateAuthorizeResponse(context);
                return;
            }

            if (context.Request.Path.Equals(MetadataPath))
            {
                await CreateMetadataResponse(context);
                return;
            }

            if (context.Request.Path.Equals(ArtifactPath) &&
                context.Request.Method == "POST")
            {
                await CreateArtifactResponse(context);
                return;
            }

            if (context.Request.Path.Equals(LogoutPath))
            {
                await CreateLogoutResponse(context);
                return;
            }

            await Next.Invoke(context);
        }

        private async Task CreateChallengeResponse(IOwinContext context)
        {
            var requestData = await context.ToHttpRequestData(Options.DataProtector.Unprotect);
            if (requestData.QueryString["SAMLRequest"].Any())
            {
                SetAuthorizationRequest(context, requestData);

                var redirect = GetAbsoluteUri(context.Request, CallbackPath);
                context.Authentication.Challenge(
                    new AuthenticationProperties
                    {
                        RedirectUri = redirect.AbsoluteUri
                    },
                    Options.AuthenticationType);
                context.Response.StatusCode = 401;
            }
            else
            {
                context.Response.StatusCode = 400;
            }
        }

        private void CreateAuthorizeResponse(IOwinContext context)
        {
            var authorizeRequest = ReadAuthorizationRequest(context);
            if (authorizeRequest == null) return;

            var bindingType = Options.BindingType;

            var serviceProvider =
                Options.ServiceProviders?.FirstOrDefault(sp => sp.EntityId.Id == authorizeRequest.Issuer.Id);
            if (serviceProvider != null)
            {
                authorizeRequest.ReturnUri = serviceProvider.AssertionConsumerServiceUri;
                bindingType = serviceProvider.BindingType;
            }

            var identity = (ClaimsIdentity) context.Request.User.Identity;
            var entityId = new EntityId(GetAbsoluteUri(context.Request, MetadataPath).AbsoluteUri);
            var response = authorizeRequest.ToSaml2Response(identity,
                Options.SigningCertificate,
                entityId,
                Options.ClaimMappings);

            Saml2Binding.Get(bindingType)
                .Bind(response)
                .Apply(context, Options.DataProtector);
        }

        private async Task CreateMetadataResponse(IOwinContext context)
        {
            var metadata = CreateIdpMetadata(context.Request)
                .ToXmlString(Options.SigningCertificate)
                .ToStream();
            context.Response.ContentType = "text/xml";
            context.Response.StatusCode = 200;
            await metadata.CopyToAsync(context.Response.Body);
        }

        private async Task CreateLogoutResponse(IOwinContext context)
        {
            var requestData = await context.ToHttpRequestData(Options.DataProtector.Unprotect);
            var binding = Saml2Binding.Get(requestData);
            if (binding == null)
            {
                context.Response.StatusCode = 400;
                return;
            }

            var unbindResult = binding.Unbind(requestData, null);
            var logoutRequest = Saml2LogoutRequest.FromXml(unbindResult.Data);

            context.Authentication.SignOut();

            var logoutResponse = new Saml2LogoutResponse(Saml2StatusCode.Success)
            {
                DestinationUrl = new Uri(new Uri(logoutRequest.Issuer.Id + "/"), "Logout"),
                SigningCertificate = Options.SigningCertificate,
                InResponseTo = new Saml2Id(logoutRequest.Id.Value),
                Issuer = new EntityId(GetAbsoluteUri(context.Request, MetadataPath).AbsoluteUri),
                RelayState = unbindResult.RelayState
            };

            Saml2Binding.Get(Saml2BindingType.HttpRedirect)
                .Bind(logoutResponse)
                .Apply(context, Options.DataProtector);
        }

        private static async Task CreateArtifactResponse(IOwinContext context)
        {
            var request = XElement.Load(context.Request.Body);

            var artifact = request
                .Element(Saml2Namespaces.SoapEnvelope + "Body")
                .Element(Saml2Namespaces.Saml2P + "ArtifactResolve")
                .Element(Saml2Namespaces.Saml2 + "Artifact")
                .Value;

            var requestId = request
                .Element(Saml2Namespaces.SoapEnvelope + "Body")
                .Element(Saml2Namespaces.Saml2P + "ArtifactResolve")
                .Attribute("ID").Value;

            var binaryArtifact = Convert.FromBase64String(artifact);

            ISaml2Message message;
            if (!Saml2ArtifactBinding.PendingMessages.TryRemove(binaryArtifact, out message))
            {
                throw new InvalidOperationException("Unknown artifact");
            }

            var xml = message.ToXml();

            if (message.SigningCertificate != null)
            {
                var xmlDoc = new XmlDocument
                {
                    PreserveWhitespace = true
                };

                xmlDoc.LoadXml(xml);
                xmlDoc.Sign(message.SigningCertificate, true);
                xml = xmlDoc.OuterXml;
            }

            var response = string.Format(
                CultureInfo.InvariantCulture,
                ResponseFormatString,
                new Saml2Id().Value,
                requestId,
                DateTime.UtcNow.ToSaml2DateTimeString(),
                xml,
                GetAbsoluteUri(context.Request, CallbackPath));

            await response.ToStream().CopyToAsync(context.Response.Body);
            context.Response.StatusCode = 200;
        }

        private ExtendedEntityDescriptor CreateIdpMetadata(IOwinRequest request, bool includeCacheDuration = true)
        {
            var metadata = new ExtendedEntityDescriptor
            {
                EntityId = new EntityId(GetAbsoluteUri(request, MetadataPath).AbsoluteUri)
            };

            if (includeCacheDuration)
            {
                metadata.CacheDuration = new TimeSpan(0, 15, 0);
                metadata.ValidUntil = DateTime.UtcNow.AddDays(1);
            }

            var idpSsoDescriptor = new IdentityProviderSingleSignOnDescriptor();
            idpSsoDescriptor.ProtocolsSupported.Add(new Uri("urn:oasis:names:tc:SAML:2.0:protocol"));
            metadata.RoleDescriptors.Add(idpSsoDescriptor);

            idpSsoDescriptor.SingleSignOnServices.Add(new ProtocolEndpoint
            {
                Binding = Saml2Binding.HttpRedirectUri,
                Location = GetAbsoluteUri(request, AuthorizePath)
            });

            idpSsoDescriptor.ArtifactResolutionServices.Add(0, new IndexedProtocolEndpoint
            {
                Index = 0,
                IsDefault = true,
                Binding = Saml2Binding.SoapUri,
                Location = GetAbsoluteUri(request, ArtifactPath)
            });

            idpSsoDescriptor.SingleLogoutServices.Add(new ProtocolEndpoint
            {
                Binding = Saml2Binding.HttpRedirectUri,
                Location = GetAbsoluteUri(request, LogoutPath)
            });

            idpSsoDescriptor.SingleLogoutServices.Add(new ProtocolEndpoint
            {
                Binding = Saml2Binding.HttpPostUri,
                Location = GetAbsoluteUri(request, LogoutPath)
            });

            var key = new KeyDescriptor(
                new SecurityKeyIdentifier(
                    new X509SecurityToken(Options.SigningCertificate)
                        .CreateKeyIdentifierClause<X509RawDataKeyIdentifierClause>()));
            idpSsoDescriptor.Keys.Add(key);

            return metadata;
        }

        private void SetAuthorizationRequest(IOwinContext context, HttpRequestData data)
        {
            var extractedMessage = Saml2Binding.Get(Saml2BindingType.HttpRedirect)
                .Unbind(data, null);

            var request = new Saml2AuthenticationRequest(
                extractedMessage.Data,
                extractedMessage.RelayState);

            var authorizeRequest = new AuthorizationRequest
            {
                InResponseTo = request.Id,
                Issuer = request.Issuer,
                ReturnUri = request.AssertionConsumerServiceUrl,
                RelayState = extractedMessage.RelayState
            };

            var serializedCookieData = authorizeRequest.Serialize();
            var protectedData = HttpRequestData.ConvertBinaryData(
                Options.DataProtector.Protect(serializedCookieData));

            context.Response.Cookies.Append(
                CookieName,
                protectedData,
                new CookieOptions
                {
                    HttpOnly = true
                });
        }

        private AuthorizationRequest ReadAuthorizationRequest(IOwinContext context)
        {
            var cookie = context.Request.Cookies[CookieName];
            if (cookie == null) return null;

            var encryptedData = cookie.GetBinaryData();
            var decryptedData = Options.DataProtector.Unprotect(encryptedData);
            var request = new AuthorizationRequest(decryptedData);
            context.Response.Cookies.Delete(
                CookieName,
                new CookieOptions
                {
                    HttpOnly = true
                });

            return request;
        }

        private static Uri GetAbsoluteUri(IOwinRequest request, PathString path)
        {
            var relative = request.PathBase + path;
            return new Uri(new Uri(request.Uri.GetLeftPart(UriPartial.Authority)), relative.Value);
        }
    }
}