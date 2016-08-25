namespace Security.HMAC
{
    using Owin;

    public static class HMACMiddlewareExtensions
    {
        public static void UseHMAC(this IAppBuilder app, HMACMiddlewareSettings settings)
        {
            app.Use<HMACMiddleware>(
                settings.AppSecretRepository,
                settings.SigningAlgorithm,
                settings.Tolerance,
                settings.Time);
        }
    }
}