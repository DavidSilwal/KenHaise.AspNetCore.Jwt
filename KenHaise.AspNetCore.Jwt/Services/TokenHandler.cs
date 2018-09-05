using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using KenHaise.AspNetCore.Jwt.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

namespace KenHaise.AspNetCore.Jwt.Services
{
    class TokenHandler : ITokenHandler
    {
        private readonly JwtSetting JwtSetting;

        public TokenHandler(JwtSetting jwtSetting)
        {
            JwtSetting = jwtSetting;
        }
        public string GenerateTokenForUser<TUser>(TUser user, DateTime? expiry = null) where TUser : IdentityUser
        {
            var expiryTime = expiry ?? DateTime.Now.AddDays(2);
            List<Claim> jwtClaims = new List<Claim>()
            {
                new Claim(JwtRegisteredClaimNames.Sub,user.Id),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToTimeStamp().ToString(),ClaimValueTypes.Integer64),
                new Claim(JwtRegisteredClaimNames.Exp, expiryTime.ToTimeStamp().ToString(),ClaimValueTypes.Integer64)
            };
            var creds = new SigningCredentials(JwtSetting.SecretKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(JwtSetting.Issuer,
                JwtSetting.Audience,
                jwtClaims,
                expires: expiryTime,
                signingCredentials: creds);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public string GenerateTokenForUser<TUser>(TUser user, Action<List<Claim>> claims, DateTime? expiry = null) where TUser : IdentityUser
        {
            var expiryTime = expiry ?? DateTime.Now.AddDays(2);
            List<Claim> jwtClaims = new List<Claim>()
            {
                new Claim(JwtRegisteredClaimNames.Sub,user.Id),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToTimeStamp().ToString(),ClaimValueTypes.Integer64),
                new Claim(JwtRegisteredClaimNames.Exp, expiryTime.ToTimeStamp().ToString(),ClaimValueTypes.Integer64)
            };

            claims(jwtClaims);
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
