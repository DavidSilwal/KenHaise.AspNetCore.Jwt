using KenHaise.AspNetCore.Jwt.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Text;

namespace KenHaise.AspNetCore.Jwt.Extensions
{
    public static class StartupExtensions
    {
        private static void AddTokenHandler<TUser>(this IServiceCollection services, Action<JwtSetting> options) where TUser: IdentityUser
        {
            var model = new JwtSetting();
            options(model);
            services.AddScoped<ITokenHandler<TUser>, TokenHandler<TUser>>(serviceProvider => new TokenHandler<TUser>(model, serviceProvider.GetRequiredService<UserManager<TUser>>()));
        }
        /// <summary>
        /// Adds a scoped service of TokenHandler using the factory specified in implementationFactory to the specified Microsoft.Extensions.DependencyInjection.IServiceCollection.
        /// </summary>
        /// <param name="builder">Authentication Builder (Used to configure authentication)</param>
        /// <param name="configureOptions">Action of type JwtBearerOptions</param>
        public static void AddJwtBearerWithTokenHandler<TUser>(this AuthenticationBuilder builder, Action<JwtBearerOptions> configureOptions) where TUser : IdentityUser
        {
            builder.AddJwtBearer(configureOptions);
            var bearerOptions = new JwtBearerOptions();
            configureOptions(bearerOptions);
            builder.Services.AddTokenHandler<TUser>(options =>
            {
                options.SecretKey = bearerOptions.TokenValidationParameters.IssuerSigningKey;
                options.Audience = bearerOptions.TokenValidationParameters.ValidIssuer;
                options.Audience = bearerOptions.TokenValidationParameters.ValidAudience;
            });
        }
        /// <summary>
        /// Adds a scoped service of TokenHandler using the factory specified in implementationFactory to the specified Microsoft.Extensions.DependencyInjection.IServiceCollection with custom authentication scheme.
        /// </summary>
        /// <param name="builder">Authentication Builder (Used to configure authentication)</param>
        /// <param name="authenticationScheme">Custom Authentication Scheme</param>
        /// <param name="configureOptions">Action of type JwtBearerOptions</param>
        public static void AddJwtBearerWithTokenHandler<TUser>(this AuthenticationBuilder builder, string authenticationScheme, Action<JwtBearerOptions> configureOptions) where TUser : IdentityUser
        {
            builder.AddJwtBearer(authenticationScheme, configureOptions);
            var bearerOptions = new JwtBearerOptions();
            configureOptions(bearerOptions);
            builder.Services.AddTokenHandler<TUser>(options =>
            {
                options.SecretKey = bearerOptions.TokenValidationParameters.IssuerSigningKey;
                options.Audience = bearerOptions.TokenValidationParameters.ValidIssuer;
                options.Audience = bearerOptions.TokenValidationParameters.ValidAudience;
            });
        }
    }
}
