using KenHaise.AspNetCore.Jwt.Demo;
using KenHaise.AspNetCore.Jwt.Demo.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Xunit;

namespace KenHaise.AspNetCore.Jwt.Test
{
    public class AuthTest : IClassFixture<ApplicationFactory<Startup>>
    {
        private readonly HttpClient client;

        public AuthTest(ApplicationFactory<Startup> factory)
        {
            client = factory.CreateClient();
        }

        [Fact]
        public async Task UnAuthorizedAccessOnAccountGetUser()
        {
            var result = await client.GetAsync("Api/Account/GetUser");

            Assert.Equal(HttpStatusCode.Unauthorized, result.StatusCode);
        }
        [Fact]
        public async Task RegisterAndLoginUser()
        {
            var model = new RegisterModel
            {
                Email = "Test@example.com",
                Password = "12345",
                ConfirmPassword = "12345",
                UserName = "TestUser"
            };
            var result = await client.PostAsJsonAsync("Api/Account/Register", model);
            Assert.Equal(HttpStatusCode.OK, result.StatusCode);

            var loginModel = new LoginModel
            {
                Email = "Test@example.com",
                Password = "12345"
            };

            var loginResult = await client.PostAsJsonAsync("Api/Account/Signin", loginModel);
            Assert.Equal(HttpStatusCode.OK, loginResult.StatusCode);
            var obj = await loginResult.Content.ReadAsAsync<LoginResult>();
            Console.WriteLine(loginResult.StatusCode);
            Assert.NotNull(obj);
            Assert.Equal("TestUser", obj.UserName);
            Assert.NotNull(obj.Token);
        }
        class LoginResult
        {
            public string Token { get; set; }
            public string UserName { get; set; }
        }

    }
}
