namespace SamlIdp.Owin
{
    #region Using Directives

    using System.Collections.Generic;
    using System.Security.Cryptography.X509Certificates;
    using Kentor.AuthServices.WebSso;

    #endregion

    public class SamlIdpOptions
    {
        public string AuthenticationType { get; set; }
        public X509Certificate2 SigningCertificate { get; set; }
        public Saml2BindingType BindingType { get; set; }
        public IDictionary<string, string> ClaimMappings { get; set; }

        public SamlIdpOptions()
        {
            BindingType = Saml2BindingType.HttpPost;
        }
    }
}