using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using KenHaise.AspNetCore.Jwt.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

namespace KenHaise.AspNetCore.Jwt.Services
{
    class TokenHandler<TUser> : ITokenHandler<TUser> where TUser:IdentityUser
    {
        private readonly JwtSetting JwtSetting;
        private readonly UserManager<TUser> userManager;

        public TokenHandler(JwtSetting jwtSetting, UserManager<TUser> userManager)
        {
            JwtSetting = jwtSetting;
            this.userManager = userManager;
        }
        public async Task<string> GenerateTokenForUser(TUser user, DateTime? expiry = null)
        {
            var expiryTime = expiry ?? DateTime.Now.AddDays(2);
            List<Claim> jwtClaims = new List<Claim>()
            {
                new Claim(JwtRegisteredClaimNames.Sub,user.Id),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToTimeStamp().ToString(),ClaimValueTypes.Integer64),
                new Claim(JwtRegisteredClaimNames.Exp, expiryTime.ToTimeStamp().ToString(),ClaimValueTypes.Integer64),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Name,user.UserName)
            };

            //Add user roles
            var roles = await userManager.GetRolesAsync(user);

            foreach (var role in roles)
            {
                jwtClaims.Add(new Claim(ClaimTypes.Role, role));
            }


            var creds = new SigningCredentials(JwtSetting.SecretKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(JwtSetting.Issuer,
                JwtSetting.Audience,
                jwtClaims,
                expires: expiryTime,
                signingCredentials: creds);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public async Task<string> GenerateTokenForUser(TUser user, Action<List<Claim>> claims, DateTime? expiry = null)
        {
            var expiryTime = expiry ?? DateTime.Now.AddDays(2);
            List<Claim> jwtClaims = new List<Claim>()
            {
                new Claim(JwtRegisteredClaimNames.Sub,user.Id),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToTimeStamp().ToString(),ClaimValueTypes.Integer64),
                new Claim(JwtRegisteredClaimNames.Exp, expiryTime.ToTimeStamp().ToString(),ClaimValueTypes.Integer64),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Name,user.UserName)
            };
            claims(jwtClaims);
            var roles = await userManager.GetRolesAsync(user);

            foreach (var role in roles)
            {
                jwtClaims.Add(new Claim(ClaimTypes.Role, role));
            }
            var creds = new SigningCredentials(JwtSetting.SecretKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(JwtSetting.Issuer,
                JwtSetting.Audience,
                jwtClaims,
                expires: expiryTime,
                signingCredentials: creds);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
