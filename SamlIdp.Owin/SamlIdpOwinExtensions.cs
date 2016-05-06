namespace SamlIdp.Owin
{
    #region Using Directives

    using global::Owin;

    #endregion

    public static class SamlIdpOwinExtensions
    {
        public static void UseSamlIdp(this IAppBuilder app, SamlIdpOptions options)
        {
            app.Use<SamlIdpMiddleware>(options);
        }
    }
}