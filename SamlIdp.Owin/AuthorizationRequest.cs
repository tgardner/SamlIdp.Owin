namespace SamlIdp.Owin
{
    using System;
    using System.Collections.Generic;
    using System.IdentityModel.Metadata;
    using System.IdentityModel.Tokens;
    using System.IO;
    using System.Linq;
    using System.Security.Claims;
    using System.Security.Cryptography.X509Certificates;
    using Kentor.AuthServices;
    using Kentor.AuthServices.Saml2P;

    internal class AuthorizationRequest
    {
        public AuthorizationRequest()
        {
        }

        public AuthorizationRequest(byte[] data)
        {
            using (var ms = new MemoryStream(data))
            using (var reader = new BinaryReader(ms))
            {
                var inResponseTo = reader.ReadString();
                if (!string.IsNullOrEmpty(inResponseTo))
                {
                    InResponseTo = new Saml2Id(inResponseTo);
                }

                var issuer = reader.ReadString();
                if (!string.IsNullOrEmpty(issuer))
                {
                    Issuer = new EntityId(issuer);
                }

                var returnUri = reader.ReadString();
                if (!string.IsNullOrEmpty(returnUri))
                {
                    ReturnUri = new Uri(returnUri);
                }

                var relayState = reader.ReadString();
                if (!string.IsNullOrEmpty(relayState))
                {
                    RelayState = relayState;
                }
            }
        }

        public Saml2Id InResponseTo { get; set; }
        public EntityId Issuer { get; set; }
        public Uri ReturnUri { get; set; }
        public string RelayState { get; set; }

        public byte[] Serialize()
        {
            using (var ms = new MemoryStream())
            using (var writer = new BinaryWriter(ms))
            {
                writer.Write(InResponseTo?.Value ?? "");
                writer.Write(Issuer?.Id ?? "");
                writer.Write(ReturnUri?.OriginalString ?? "");
                writer.Write(RelayState ?? "");
                return ms.ToArray();
            }
        }

        public Saml2Response ToSaml2Response(ClaimsIdentity identity,
            X509Certificate2 signingCertificate,
            EntityId entityId,
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

            return new Saml2Response(
                entityId,
                signingCertificate, ReturnUri,
                InResponseTo, RelayState, new Uri(Issuer.Id), identity);
        }
    }
}