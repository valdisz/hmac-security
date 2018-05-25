namespace Security.HMAC
{
    using System.Security.Cryptography;
    using Microsoft.AspNetCore.Builder;
    using Microsoft.Extensions.Configuration;
    using Microsoft.Extensions.DependencyInjection;

    public static class HmacMiddlewareExtensions
    {
        public static IApplicationBuilder UseHmac(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<HmacMiddleware>();
        }

        public static void AddHmac(this IServiceCollection services,
            IConfigurationSection configurationSection)
        {
            services.Configure<HmacMiddlewareOptions>(configurationSection);
            services.AddHmac(
                new SecretsFromConfig(configurationSection.GetSection("Secrets")),
                new HmacSigningAlgorithm(secret => new HMACSHA256(secret)));
        }

        public static void AddHmac(this IServiceCollection services,
            IAppSecretRepository repository,
            ISigningAlgorithm algorithm)
        {
            services.AddSingleton<ITime, SystemTime>();
            services.AddSingleton(algorithm);
            services.AddSingleton(repository);
        }
    }
}