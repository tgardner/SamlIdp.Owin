namespace SampleIdentityServer3.Configuration
{
    using System.Collections.Generic;
    using IdentityServer3.Core.Models;

    public static class Clients
    {
        public static IEnumerable<Client> Get()
        {
            return new[]
            {
                new Client
                {
                    Enabled = true,
                    ClientName = "SAML IdP Client",
                    ClientId = "samlidp",
                    Flow = Flows.Hybrid,
                    RequireConsent = false,
                    ClientSecrets = new List<Secret>
                    {
                        new Secret("example123")
                    },
                    RedirectUris = new List<string>
                    {
                        "http://localhost:12345/saml"
                    },
                    AllowAccessToAllScopes = true,
                    AlwaysSendClientClaims = true
                }
            };
        } 
    }
}