namespace Security.HMAC
{
    using System;
    using System.Security;
    using Microsoft.Owin;

    internal static class RequestTools
    {
        internal static bool Validate(IOwinRequest req, ISigningAlgorithm signingAlgorithm, IAppSecretRepository appSecretRepository, ITime time, TimeSpan tolerance)
        {
            var h = req.Headers;

            var appId = GetAppId(req);
            var nonce = GetNonce(req);

            var auth = h.Get(Headers.Authorization)?.Split(' ');
            var authSchema = auth?.Length == 2 ? auth[0] : null;
            var authValue = auth?.Length == 2 ? auth[1] : null;
            DateTimeOffset date =
                DateTimeOffset.TryParse(h.Get(Headers.Date), out date)
                    ? date
                    : DateTimeOffset.MinValue;

            if (appId != null
                && authSchema == Schemas.HMAC
                && authValue != null
                && time.UtcNow - date <= tolerance)
            {
                var builder = new CannonicalRepresentationBuilder();
                var content = builder.BuildRepresentation(
                    nonce,
                    appId,
                    req.Method,
                    req.ContentType,
                    req.Accept,
                    Convert.FromBase64String(h.Get(Headers.ContentMD5)),
                    date,
                    req.Uri);

                SecureString secret;
                if (content != null && (secret = appSecretRepository.GetSecret(appId)) != null)
                {
                    var signature = signingAlgorithm.Sign(secret, content);
                    if (authValue == signature)
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        public static string GetAppId(IOwinRequest req) => req.Headers.Get(Headers.XAppId);

        public static string GetNonce(IOwinRequest req) => req.Headers.Get(Headers.XNonce);
    }
}