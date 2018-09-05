using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;

namespace KenHaise.AspNetCore.Jwt.Services
{
    public interface ITokenHandler
    {
        /// <summary>
        /// Generates token for the custom implementation of user TUser
        /// </summary>
        /// <typeparam name="TUser">Type of the users object</typeparam>
        /// <param name="user">implementation of user derived from IdentityUser</param>
        /// <param name="expiry">Expiry time for token, default is 2 days</param>
        /// <returns>String of token</returns>
        string GenerateTokenForUser<TUser>(TUser user, DateTime? expiry = null) where TUser : IdentityUser;
        /// <summary>
        /// Generates token with extra claims for the custom implementation of user TUser
        /// </summary>
        /// <typeparam name="TUser">Type of the users object</typeparam>
        /// <param name="user">implementation of user derived from IdentityUser</param>
        /// <param name="claims">Action of type List<Claim></param>
        /// <param name="expiry">Expiry time for token, default is 2 days</param>
        /// <returns>String of token</returns>
        string GenerateTokenForUser<TUser>(TUser user, Action<List<Claim>> claims, DateTime? expiry = null) where TUser : IdentityUser;
    }
}
