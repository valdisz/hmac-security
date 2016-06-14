namespace Security.HMAC
{
    using System;
    using System.Collections.Generic;
    using System.Text;
    using System.Threading.Tasks;
    using Microsoft.Owin;

    public class HmacMiddleware : OwinMiddleware
    {
        public const string XAppId = "X-HMAC-App-Id";
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
            var rawAuth = ch.HeaderValues("Authentication");
            var appId = ch.HeaderValue(XAppId);
            var nonce = ch.HeaderValue(XNonce);
            var secret = appSecretRepository.GetSecret(appId);
            ch.Unless(() => !string.IsNullOrWhiteSpace(secret));
            ch.Unless(() => rawAuth.Count == 2);
            ch.Unless(() => string.Equals(Schema, rawAuth[0], StringComparison.OrdinalIgnoreCase));
            ch.Unless(() => !string.IsNullOrWhiteSpace(rawAuth[1]));

            if (ch.Challenged)
            {
                ch.WriteChallengeResponse();
                return;
            }

            List<string> signingParts = new List<string>
            {
                nonce,
                appId,
                req.Method,
                req.Protocol,
                req.ContentType,
                req.Uri.ToString(),
                Encoding.UTF8.GetString(hashingAlgorithm.ComputeHash(req.Body))
            };

            byte[] secretBytes = Encoding.UTF8.GetBytes(secret);
            byte[] contentBytes = Encoding.UTF8.GetBytes(string.Join("", signingParts));

            string requestSignature = rawAuth[1];
            byte[] computedSignatureBytes = signingAlgorithm.Sign(secretBytes, contentBytes);
            var computedSignature = Convert.ToBase64String(computedSignatureBytes);

            ch.Unless(() => requestSignature == computedSignature);
            if (ch.Challenged)
            {
                ch.WriteChallengeResponse();
                return;
            }

            await Next.Invoke(context);
        }
    }
}
