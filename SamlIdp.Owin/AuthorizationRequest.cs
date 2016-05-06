namespace SamlIdp.Owin
{
    #region Using Directives

    using System;
    using System.Collections.Generic;
    using System.IdentityModel.Metadata;
    using System.IdentityModel.Tokens;
    using System.Linq;
    using System.Security.Claims;
    using System.Security.Cryptography.X509Certificates;
    using Kentor.AuthServices;
    using Kentor.AuthServices.Saml2P;

    #endregion

    internal class AuthorizationRequest
    {
        public string InResponseTo { get; set; }
        public string Audience { get; set; }
        public string RelayState { get; set; }
        public string AssertionConsumerServiceUrl { get; set; }

        public Saml2Response ToSaml2Response(ClaimsIdentity identity, 
            X509Certificate2 signingCertificate,
            string entityId,
            IDictionary<string, string> claimMappings = null)
        {
            if (claimMappings != null)
            {
                var claimsIdentity = identity;
                var claims = from claimMapping in claimMappings
                    let claim = claimsIdentity.Claims.FirstOrDefault(c => c.Type == claimMapping.Value)
                    where claim != null
                    select new Claim(claimMapping.Key, claim.Value);

                identity = new ClaimsIdentity(claims);
            }

            var nameIdClaim = identity.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier);
            if (nameIdClaim != null)
            {
                nameIdClaim.Properties[ClaimProperties.SamlNameIdentifierFormat] =
                    NameIdFormat.Unspecified.GetUri().AbsoluteUri;
            }

            Saml2Id saml2Id = null;
            if (!string.IsNullOrEmpty(InResponseTo))
            {
                saml2Id = new Saml2Id(InResponseTo);
            }

            var audienceUrl = string.IsNullOrEmpty(Audience)
                ? null
                : new Uri(Audience);

            return new Saml2Response(
                new EntityId(entityId),
                signingCertificate, new Uri(AssertionConsumerServiceUrl),
                saml2Id, RelayState, audienceUrl, identity);
        }
    }
}