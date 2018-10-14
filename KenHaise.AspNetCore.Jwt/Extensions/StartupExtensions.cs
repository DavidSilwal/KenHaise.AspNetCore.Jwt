using KenHaise.AspNetCore.Jwt.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;

namespace KenHaise.AspNetCore.Jwt.Extensions
{
    public static class StartupExtensions
    {
        private static void AddTokenHandler<TUser>(this IServiceCollection services, TokenValidationParameters tokenValidationParameters) where TUser: IdentityUser
        {
            services.AddScoped<ITokenHandler<TUser>, TokenHandler<TUser>>(serviceProvider => new TokenHandler<TUser>(tokenValidationParameters, serviceProvider.GetRequiredService<UserManager<TUser>>()));
        }
        /// <summary>
        /// Adds a scoped service of TokenHandler using the factory specified in implementationFactory to the specified Microsoft.Extensions.DependencyInjection.IServiceCollection.
        /// </summary>
        /// <param name="builder">Authentication Builder (Used to configure authentication)</param>
        /// <param name="configureOptions">Action of type JwtBearerOptions</param>
        public static void AddJwtBearerWithTokenHandler<TUser>(this AuthenticationBuilder builder, Action<JwtBearerOptions> configureOptions) where TUser : IdentityUser
        {
            var bearerOptions = new JwtBearerOptions();
            configureOptions(bearerOptions);
            builder.AddJwtBearer(configureOptions);
            builder.Services.AddTokenHandler<TUser>(bearerOptions.TokenValidationParameters);
        }
        /// <summary>
        /// Adds a scoped service of TokenHandler using the factory specified in implementationFactory to the specified Microsoft.Extensions.DependencyInjection.IServiceCollection with custom authentication scheme.
        /// </summary>
        /// <param name="builder">Authentication Builder (Used to configure authentication)</param>
        /// <param name="authenticationScheme">Custom Authentication Scheme</param>
        /// <param name="configureOptions">Action of type JwtBearerOptions</param>
        public static void AddJwtBearerWithTokenHandler<TUser>(this AuthenticationBuilder builder, string authenticationScheme, Action<JwtBearerOptions> configureOptions) where TUser : IdentityUser
        {
            var bearerOptions = new JwtBearerOptions();
            configureOptions(bearerOptions);
            builder.AddJwtBearer(authenticationScheme, configureOptions);
            builder.Services.AddTokenHandler<TUser>(bearerOptions.TokenValidationParameters);
        }
    }
}
