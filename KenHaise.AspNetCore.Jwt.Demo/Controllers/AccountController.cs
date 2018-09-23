using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using KenHaise.AspNetCore.Jwt.Demo.Models;
using KenHaise.AspNetCore.Jwt.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace KenHaise.AspNetCore.Jwt.Demo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ITokenHandler<IdentityUser> _tokenHandler;
        public AccountController(UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            ITokenHandler<IdentityUser> tokenHandler)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _tokenHandler = tokenHandler;
        }
        [HttpGet("[action]")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<IActionResult> GetUser()
        {
            var user = await _userManager.GetUserAsync(User);
            return Ok($"You are logged in {user.ToString()}");
        }
        [HttpPost("[action]")]
        public async Task<IActionResult> SignIn([FromBody] LoginModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);

            if (user == null)
            {
                ModelState.AddModelError("email", $"No user exists with email {model.Email}");
                return BadRequest(ModelState);
            }
            var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, false);
            if (result.Succeeded)
            {
                var token = await _tokenHandler.GenerateTokenForUser(user, claims =>
                {
                    claims.Add(new Claim(ClaimTypes.Email, user.Email));
                },expiry: DateTime.Now.AddMinutes(20));
                return Ok(new { token, user.UserName });
            }
            ModelState.AddModelError("password", $"Invalid password");
            return BadRequest(ModelState);
        }

        [HttpPost("[action]")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user != null)
            {
                ModelState.AddModelError("email", $"User already exists with email {model.Email}");
                return BadRequest(ModelState);
            }
            var myuser = new IdentityUser { UserName = model.UserName, Email = model.Email };
            var SignUpresult = await _userManager.CreateAsync(myuser, model.Password);
            if (SignUpresult.Succeeded)
            {
                return Ok(new { data = "Signup successful" });
            }
            ModelState.AddModelError("username", $"Username {model.UserName} is taken");
            return BadRequest(ModelState);
        }

    }
}