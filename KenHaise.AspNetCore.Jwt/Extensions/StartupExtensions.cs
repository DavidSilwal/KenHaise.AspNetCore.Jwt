using KenHaise.AspNetCore.Jwt.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Text;

namespace KenHaise.AspNetCore.Jwt.Extensions
{
    public static class StartupExtensions
    {
        private static void AddTokenHandler(this IServiceCollection services, Action<JwtSetting> options)
        {
            var model = new JwtSetting();
            options(model);
            services.AddScoped<ITokenHandler, TokenHandler>(serviceProvider => new TokenHandler(model));
        }
        /// <summary>
        /// Adds a scoped service of TokenHandler using the factory specified in implementationFactory to the specified Microsoft.Extensions.DependencyInjection.IServiceCollection.
        /// </summary>
        /// <param name="builder">Authentication Builder (Used to configure authentication)</param>
        /// <param name="configureOptions">Action of type JwtBearerOptions</param>
        public static void AddJwtBearerWithTokenHandler(this AuthenticationBuilder builder, Action<JwtBearerOptions> configureOptions)
        {
            builder.AddJwtBearer(configureOptions);
            var bearerOptions = new JwtBearerOptions();
            configureOptions(bearerOptions);
            builder.Services.AddTokenHandler(options =>
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
        public static void AddJwtBearerWithTokenHandler(this AuthenticationBuilder builder, string authenticationScheme, Action<JwtBearerOptions> configureOptions)
        {
            builder.AddJwtBearer(authenticationScheme, configureOptions);
            var bearerOptions = new JwtBearerOptions();
            configureOptions(bearerOptions);
            builder.Services.AddTokenHandler(options =>
            {
                options.SecretKey = bearerOptions.TokenValidationParameters.IssuerSigningKey;
                options.Audience = bearerOptions.TokenValidationParameters.ValidIssuer;
                options.Audience = bearerOptions.TokenValidationParameters.ValidAudience;
            });
        }
    }
}
