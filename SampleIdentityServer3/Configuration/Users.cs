namespace SampleIdentityServer3.Configuration
{
    using System;
    using System.Collections.Generic;
    using IdentityServer3.Core.Services.InMemory;

    public static class Users
    {
        public static List<InMemoryUser> Get()
        {
            return new List<InMemoryUser>
            {
                new InMemoryUser
                {
                    Username = "JohnDoe",
                    Password = "password",
                    Subject = Guid.NewGuid().ToString()
                }
            };
        } 
    }
}