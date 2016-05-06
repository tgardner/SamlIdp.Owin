namespace SamlIdp.Owin
{
    using System;
    using System.IO;

    internal static class StringExtensions
    {
        public static Stream ToStream(this string s)
        {
            var stream = new MemoryStream();
            var writer = new StreamWriter(stream);
            writer.Write(s);
            writer.Flush();
            stream.Position = 0;
            return stream;
        }

        public static byte[] GetBinaryData(this string cookieData)
        {
            return Convert.FromBase64String(
                cookieData
                    .Replace('_', '/')
                    .Replace('-', '+')
                    .Replace('.', '='));
        }
    }
}