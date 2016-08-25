namespace Security.HMAC
{
    using Owin;

    public static class HmacMiddlewareExtensions
    {
        public static void UseHmac(this IAppBuilder app, HmacMiddlewareOptions options)
        {
            app.Use<HmacMiddleware>(
                options.AppSecretRepository,
                options.SigningAlgorithm,
                options.Tolerance,
                options.Time);
        }

        public static void UseHmacAuthentication(this IAppBuilder app, HmacAuthenticationOptions options)
        {
            app.Use<HmacAuthenticationMiddleware>(options);
        }
    }
}