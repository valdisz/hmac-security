namespace Security.HMAC
{
    using System;
    using System.Security;
    using System.Text;
    using Microsoft.Owin;

    internal static class RequestTools
    {
        internal static bool Validate(IOwinRequest req, ISigningAlgorithm algorithm, ISecretRepository secretRepository, ITime time, TimeSpan clockSkew)
        {
            var h = req.Headers;

            var client = GetClient(req);
            var nonce = GetNonce(req);

            var auth = h.Get(Headers.Authorization)?.Split(' ');
            var scheme = auth?.Length == 2 ? auth[0] : null;
            var token = auth?.Length == 2 ? auth[1] : null;
            DateTimeOffset date =
                DateTimeOffset.TryParse(h.Get(Headers.Date), out date)
                    ? date
                    : DateTimeOffset.MinValue;

            if (client != null
                && nonce != null
                && scheme == Schemas.Bearer
                && token != null
                && time.UtcNow - date <= clockSkew)
            {
                var contentMd5 = h.Get(Headers.ContentMD5);
                var builder = new CannonicalRepresentationBuilder();
                var content = builder.BuildRepresentation(
                    nonce,
                    client,
                    req.Method,
                    req.ContentType,
                    req.Accept.Split(','),
                    contentMd5 == null ? null : Convert.FromBase64String(contentMd5),
                    date,
                    req.Uri);


                SecureString secret = secretRepository.GetSecret(client);
                if (secret != null)
                {
                    var isTokenValid = algorithm.Verify(
                        secret,
                        Encoding.UTF8.GetBytes(content),
                        Convert.FromBase64String(token));

                    if (isTokenValid)
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        public static string GetClient(IOwinRequest req) => req.Headers.Get(Headers.XClient);

        public static string GetNonce(IOwinRequest req) => req.Headers.Get(Headers.XNonce);
    }
}