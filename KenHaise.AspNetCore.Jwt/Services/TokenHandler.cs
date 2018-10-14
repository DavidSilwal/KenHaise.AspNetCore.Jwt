using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using KenHaise.AspNetCore.Jwt.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;

namespace KenHaise.AspNetCore.Jwt.Services
{
    class TokenHandler<TUser> : ITokenHandler<TUser> where TUser:IdentityUser
    {
        private readonly TokenValidationParameters tokenValidationParameters;
        private readonly UserManager<TUser> userManager;

        public TokenHandler(TokenValidationParameters tokenValidationParameters, UserManager<TUser> userManager)
        {
            this.tokenValidationParameters = tokenValidationParameters;
            this.userManager = userManager;
        }
        public async Task<string> GenerateTokenForUser(TUser user, DateTime? expiry = null)
        {
            var expiryTime = expiry ?? DateTime.Now.AddDays(2);
            var jwtClaims = await GetDefaultClaimsForUser(user, expiryTime);
            var creds = new SigningCredentials(tokenValidationParameters.IssuerSigningKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(tokenValidationParameters.ValidIssuer,
                tokenValidationParameters.ValidAudience,
                jwtClaims,
                expires: expiryTime,
                signingCredentials: creds);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public async Task<string> GenerateTokenForUser(TUser user, Action<List<Claim>> claims, DateTime? expiry = null)
        {
            var expiryTime = expiry ?? DateTime.Now.AddDays(2);
            var jwtClaims = new List<Claim>();
            claims(jwtClaims);
            jwtClaims.AddRange(await GetDefaultClaimsForUser(user, expiryTime));
            var creds = new SigningCredentials(tokenValidationParameters.IssuerSigningKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(tokenValidationParameters.ValidIssuer,
                tokenValidationParameters.ValidAudience,
                jwtClaims,
                expires: expiryTime,
                signingCredentials: creds);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        

        public async Task<string> RefreshTokenAsync(string token, DateTime? expiry = null)
        {
            var expiryTime = expiry ?? DateTime.Now.AddDays(2);
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var principal = jwtTokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
            if (!(securityToken is JwtSecurityToken jwtSecurityToken) || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");
            var creds = new SigningCredentials(tokenValidationParameters.IssuerSigningKey, SecurityAlgorithms.HmacSha256);

            var jwtClaims = principal.Claims.Where(a => a.Type != JwtRegisteredClaimNames.Exp && a.Type != ClaimTypes.Role).ToList();

            await UpdateClaimsAsync(jwtClaims);

            jwtClaims.Add(new Claim(JwtRegisteredClaimNames.Exp, expiryTime.ToTimeStamp().ToString(), ClaimValueTypes.Integer64));
            var newToken = new JwtSecurityToken(tokenValidationParameters.ValidIssuer,
                tokenValidationParameters.ValidAudience,
                jwtClaims,
                expires: expiryTime,
                signingCredentials: creds);
            return new JwtSecurityTokenHandler().WriteToken(newToken);
        }


        public async Task<string> RefreshTokenAsync(string token, Action<List<Claim>> claims, DateTime? expiry = null)
        {
            var expiryTime = expiry ?? DateTime.Now.AddDays(2);
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var principal = jwtTokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
            if (!(securityToken is JwtSecurityToken jwtSecurityToken) || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");
            var creds = new SigningCredentials(tokenValidationParameters.IssuerSigningKey, SecurityAlgorithms.HmacSha256);


            var jwtClaims = new List<Claim>();
            claims(jwtClaims);
            jwtClaims.AddRange(principal.Claims.Where(a => a.Type != JwtRegisteredClaimNames.Exp && a.Type != ClaimTypes.Role).ToList());
            await UpdateClaimsAsync(jwtClaims);
            jwtClaims.Add(new Claim(JwtRegisteredClaimNames.Exp, expiryTime.ToTimeStamp().ToString(), ClaimValueTypes.Integer64));
            var newToken = new JwtSecurityToken(tokenValidationParameters.ValidIssuer,
                tokenValidationParameters.ValidAudience,
                jwtClaims,
                expires: expiryTime,
                signingCredentials: creds);
            return new JwtSecurityTokenHandler().WriteToken(newToken);
        }

        public Task<string> RefreshTokenAsync(StringValues authorizationHeader, DateTime? expiry = null)
        {
            var token = authorizationHeader.ToString().Split("Bearer ")[1];
            if (string.IsNullOrWhiteSpace(token))
            {
                throw new UnauthorizedAccessException();
            }
            return RefreshTokenAsync(token, expiry);
        }

        public Task<string> RefreshTokenAsync(StringValues authorizationHeader, Action<List<Claim>> claims, DateTime? expiry = null)
        {
            var token = authorizationHeader.ToString().Split("Bearer ")[1];
            if (string.IsNullOrWhiteSpace(token))
            {
                throw new UnauthorizedAccessException();
            }
            return RefreshTokenAsync(token, expiry);
        }

        #region PrivateHelperMethods
        private async Task<List<Claim>> GetDefaultClaimsForUser(TUser user, DateTime expiryTime)
        {
            List<Claim> jwtClaims = new List<Claim>()
            {
                new Claim(JwtRegisteredClaimNames.Sub,user.Id),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToTimeStamp().ToString(),ClaimValueTypes.Integer64),
                new Claim(JwtRegisteredClaimNames.Exp, expiryTime.ToTimeStamp().ToString(),ClaimValueTypes.Integer64),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Name,user.UserName)
            };
            await AddRoles(user, jwtClaims);
            return jwtClaims;
        }

        private async Task UpdateClaimsAsync(List<Claim> claims)
        {
            var id = claims.SingleOrDefault(a => a.Type == ClaimTypes.NameIdentifier).Value;
            if (id is null)
            {
                throw new UnauthorizedAccessException();
            }
            var user = await userManager.FindByIdAsync(id);
            if (user == null)
            {
                throw new UnauthorizedAccessException();
            }
            await AddRoles(user, claims);

        }
        private async Task AddRoles(TUser user, List<Claim> jwtClaims)
        {
            if (userManager.SupportsUserRole)
            {
                var roles = await userManager.GetRolesAsync(user);

                foreach (var role in roles)
                {
                    jwtClaims.Add(new Claim(ClaimTypes.Role, role));
                }
            }
        }
        #endregion

    }
}
