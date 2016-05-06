namespace SampleIdentityServer3
{
    using System;
    using System.Security.Cryptography.X509Certificates;
    using Configuration;
    using IdentityServer3.Core.Configuration;
    using IdentityServer3.Core.Models;
    using Microsoft.Owin;
    using Microsoft.Owin.Security.Cookies;
    using Microsoft.Owin.Security.OpenIdConnect;
    using Owin;
    using SamlIdp.Owin;

    public class Startup
    {
        private static readonly X509Certificate2 SigningCertificate =
            new X509Certificate2(AppDomain.CurrentDomain.BaseDirectory +
                                 "\\Kentor.AuthServices.SampleIdentityServer3.pfx");

        public void Configuration(IAppBuilder app)
        {
#if DEBUG
            app.UseErrorPage();
#endif
            app.UseWelcomePage("/");

            app.Map("/core", coreApp =>
            {
                var options = new IdentityServerOptions
                {
                    SiteName = "Embedded IdentityServer",

                    Factory = new IdentityServerServiceFactory()
                        .UseInMemoryScopes(StandardScopes.All)
                        .UseInMemoryClients(Clients.Get())
                        .UseInMemoryUsers(Users.Get()),

                    RequireSsl = false,

                    AuthenticationOptions = new AuthenticationOptions
                    {
                        EnableAutoCallbackForFederatedSignout = true,
                        EnableSignOutPrompt = false
                    },

                    SigningCertificate = SigningCertificate

                };
                coreApp.UseIdentityServer(options);
            });

            app.Map("/saml", samlApp =>
            {
                samlApp.UseCookieAuthentication(new CookieAuthenticationOptions
                {
                    AuthenticationType = "Cookies"
                });

                samlApp.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
                {
                    Authority = "http://localhost:12345/core",
                    ClientId = "samlidp",
                    ClientSecret = "b2a5509386414dc38d48a3897de9e519",
                    RedirectUri = "http://localhost:12345/saml",
                    ResponseType = "code id_token token",
                    Scope = "openid",
                    SignInAsAuthenticationType = "Cookies"
                });

                var options = new SamlIdpOptions
                {
                    AuthenticationType = OpenIdConnectAuthenticationDefaults.AuthenticationType,
                    SigningCertificate = SigningCertificate
                };
                samlApp.UseSamlIdp(options);
            });
        }
    }
}