namespace SamlIdp.Owin
{
    using System;
    using System.IdentityModel.Metadata;
    using Kentor.AuthServices.WebSso;

    public class ServiceProvider
    {
        public ServiceProvider()
        {
            BindingType = Saml2BindingType.HttpPost;
        }

        public EntityId EntityId { get; set; }
        public Uri AssertionConsumerServiceUri { get; set; }
        public Saml2BindingType BindingType { get; set; }
    }
}