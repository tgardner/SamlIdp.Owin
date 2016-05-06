namespace SamlIdp.Owin
{
    using System;
    using Kentor.AuthServices.WebSso;
    using Microsoft.Owin;
    using Microsoft.Owin.Security.DataProtection;

    internal static class CommandResultExtensions
    {
        public static void Apply(this CommandResult commandResult,
            IOwinContext context,
            IDataProtector dataProtector)
        {
            if (commandResult == null)
            {
                throw new ArgumentNullException(nameof(commandResult));
            }

            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.Response.ContentType = commandResult.ContentType;
            context.Response.StatusCode = (int) commandResult.HttpStatusCode;

            if (commandResult.Location != null)
            {
                context.Response.Headers["Location"] = commandResult.Location.OriginalString;
            }

            if (commandResult.Content != null)
            {
                context.Response.ContentLength = null;
                context.Response.Write(commandResult.Content);
            }

            if (commandResult.TerminateLocalSession)
            {
                context.Authentication.SignOut();
            }

            ApplyCookies(commandResult, context, dataProtector);
        }

        private static void ApplyCookies(CommandResult commandResult, IOwinContext context, IDataProtector dataProtector)
        {
            var serializedCookieData = commandResult.GetSerializedRequestState();

            if (serializedCookieData != null)
            {
                var protectedData = HttpRequestData.ConvertBinaryData(
                    dataProtector.Protect(serializedCookieData));

                context.Response.Cookies.Append(
                    commandResult.SetCookieName,
                    protectedData,
                    new CookieOptions
                    {
                        HttpOnly = true
                    });
            }

            commandResult.ApplyClearCookie(context);
        }

        public static void ApplyClearCookie(this CommandResult commandResult, IOwinContext context)
        {
            if (!string.IsNullOrEmpty(commandResult.ClearCookieName))
            {
                context.Response.Cookies.Delete(
                    commandResult.ClearCookieName,
                    new CookieOptions
                    {
                        HttpOnly = true
                    });
            }
        }
    }
}