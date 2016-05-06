// ReSharper disable once CheckNamespace

namespace Owin
{
    using System;
    using SamlIdp.Owin;

    public static class SamlIdpOwinExtensions
    {
        public static void UseSamlIdp(this IAppBuilder app, SamlIdpOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            app.Use<SamlIdpMiddleware>(app, options);
        }
    }
}