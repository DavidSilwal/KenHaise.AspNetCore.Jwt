using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Primitives;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace KenHaise.AspNetCore.Jwt.Services
{
    public interface ITokenHandler<TUser> where TUser: IdentityUser
    {
        /// <summary>
        /// Generates token for the custom implementation of user TUser
        /// </summary>
        /// <typeparam name="TUser">Type of the users object</typeparam>
        /// <param name="user">implementation of user derived from IdentityUser</param>
        /// <param name="expiry">Expiry time for token, default is 2 days</param>
        /// <returns>String of token</returns>
        Task<string> GenerateTokenForUser(TUser user, DateTime? expiry = null);
        /// <summary>
        /// Generates token with extra claims for the custom implementation of user TUser
        /// </summary>
        /// <typeparam name="TUser">Type of the users object</typeparam>
        /// <param name="user">implementation of user derived from IdentityUser</param>
        /// <param name="claims">Action of type List<Claim></param>
        /// <param name="expiry">Expiry time for token, default is 2 days</param>
        /// <returns>String of token</returns>
        Task<string> GenerateTokenForUser(TUser user, Action<List<Claim>> claims, DateTime? expiry = null);

        /// <summary>
        /// Generates new token with old token.The new token has all claims of previous token as well as new roles.
        /// </summary>
        /// <param name="token">Old token</param>
        /// <param name="expiry">expiry for new token</param>
        /// <returns>Task for new Token</returns>
        Task<string> RefreshTokenAsync(string token, DateTime? expiry = null);

        /// <summary>
        /// Generates new token with old token.The new token has all claims of previous token as well as new roles.
        /// </summary>
        /// <param name="token">Old token</param>
        /// <param name="expiry">expiry for new token</param>
        /// <returns>Task for new Token</returns>
        Task<string> RefreshTokenAsync(string token, Action<List<Claim>> claims, DateTime? expiry = null);


        Task<string> RefreshTokenAsync(StringValues authorizationHeader, DateTime? expiry = null);
        Task<string> RefreshTokenAsync(StringValues authorizationHeader, Action<List<Claim>> claims, DateTime? expiry = null);

    }
}
