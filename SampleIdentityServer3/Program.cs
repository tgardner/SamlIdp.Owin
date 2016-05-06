namespace SampleIdentityServer3
{
    using System;
    using Microsoft.Owin.Hosting;

    internal class Program
    {
        private static void Main(string[] args)
        {
            const string url = "http://localhost:12345";
            using (WebApp.Start<Startup>(url))
            {
                Console.WriteLine("Listening at {0}", url);
                Console.ReadLine();
            }
        }
    }
}