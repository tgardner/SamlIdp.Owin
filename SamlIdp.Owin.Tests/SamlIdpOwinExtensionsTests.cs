namespace SamlIdp.Owin.Tests
{
    using global::Owin;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using NSubstitute;

    [TestClass]
    public class SamlIdpOwinExtensionsTests
    {
        [TestMethod]
        public void SamlIdpOwinExtensions_UseSamlIdp()
        {
            var app = Substitute.For<IAppBuilder>();

            var options = new SamlIdpOptions();

            app.UseSamlIdp(options);

            app.Received().Use(typeof (SamlIdpMiddleware), app, options);
        }
    }
}