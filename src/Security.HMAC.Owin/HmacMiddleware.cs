namespace Security.HMAC
{
    using System;
    using System.Collections.Generic;
    using System.Text;
    using System.Threading.Tasks;
    using Microsoft.Owin;

    public class HmacMiddleware : OwinMiddleware
    {
        public const string XAppId = "X-HMAC-AppId";
        public const string XNonce = "X-HMAC-Nonce";
        public const string Schema = "HMAC";

        private readonly IAppSecretRepository appSecretRepository;
        private readonly IHashingAlgorithm hashingAlgorithm;
        private readonly ISigningAlgorithm signingAlgorithm;

        public HmacMiddleware(
            IAppSecretRepository appSecretRepository,
            IHashingAlgorithm hashingAlgorithm,
            ISigningAlgorithm signingAlgorithm,
            OwinMiddleware next) : base(next)
        {
            this.appSecretRepository = appSecretRepository;
            this.hashingAlgorithm = hashingAlgorithm;
            this.signingAlgorithm = signingAlgorithm;
        }

        public override async Task Invoke(IOwinContext context)
        {
            var req = context.Request;
            var res = context.Response;

            Challenger ch = new Challenger(req, res);

            var auth       = ch.EnsureHeaderValues("Authentication");
            var appId      = ch.EnsureHeaderValue(XAppId);
            var nonce      = ch.EnsureHeaderValue(XNonce);
            var authSchema = auth.Count == 2 ? auth[0] : null;
            var authValue  = auth.Count == 2 ? auth[1] : null;
            var secret     = appSecretRepository.GetSecret(appId);

            ch.Unless(secret != null);
            ch.Unless(string.Equals(Schema, authSchema, StringComparison.OrdinalIgnoreCase));
            ch.Unless(!string.IsNullOrWhiteSpace(authValue));

            if (!ch.ShouldChallenge)
            {
                List<string> content = new List<string>
                {
                    nonce,
                    appId,
                    req.Method,
                    req.Protocol,
                    req.ContentType,
                    req.Uri.ToString(),
                    Encoding.UTF8.GetString(hashingAlgorithm.ComputeHash(req.Body))
                };

                byte[] contentBytes = Encoding.UTF8.GetBytes(string.Join("", content));
                byte[] secretBytes = secret.ToByteArray(Encoding.UTF8);

                byte[] signatureBytes = signingAlgorithm.Sign(secretBytes, contentBytes);
                var signature = Convert.ToBase64String(signatureBytes);

                ch.Unless(authValue == signature);
            }

            if (ch.ShouldChallenge)
                ch.WriteChallengeResponse();
            else
                await Next.Invoke(context);
        }
    }
}
