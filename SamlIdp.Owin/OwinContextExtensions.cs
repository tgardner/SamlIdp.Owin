namespace SamlIdp.Owin
{
    using System;
    using System.Threading.Tasks;
    using Kentor.AuthServices.WebSso;
    using Microsoft.Owin;

    internal static class OwinContextExtensions
    {
        public static async Task<HttpRequestData> ToHttpRequestData(
            this IOwinContext context,
            Func<byte[], byte[]> cookieDecryptor)
        {
            if (context == null)
            {
                return null;
            }

            IFormCollection formData = null;
            if (context.Request.Body != null)
            {
                formData = await context.Request.ReadFormAsync();
            }

            var applicationRootPath = context.Request.PathBase.Value;
            if (string.IsNullOrEmpty(applicationRootPath))
            {
                applicationRootPath = "/";
            }

            return new HttpRequestData(
                context.Request.Method,
                context.Request.Uri,
                applicationRootPath,
                formData,
                context.Request.Cookies,
                cookieDecryptor);
        }
    }
}