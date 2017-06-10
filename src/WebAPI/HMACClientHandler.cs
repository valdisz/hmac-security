namespace Security.HMAC
{
    using System;
    using System.Linq;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Security;
    using System.Text;
    using System.Threading;

    public sealed class HmacClientHandler : MessageProcessingHandler
    {
        private readonly string client;
        private readonly SecureString secret;
        private readonly ISigningAlgorithm signingAlgorithm;
        private readonly INonceGenerator nonceGenerator;
        private readonly ITime time;

        public HmacClientHandler(
            string client,
            SecureString secret,
            ISigningAlgorithm signingAlgorithm,
            INonceGenerator nonceGenerator = null,
            ITime time = null)
        {
            this.client = client;
            this.secret = secret;
            this.signingAlgorithm = signingAlgorithm;
            this.nonceGenerator = nonceGenerator ?? GuidNonceGenerator.Instance;
            this.time = time ?? SystemTime.Instance;
        }

        public HmacClientHandler(
            HttpMessageHandler innerHandler,
            string client,
            SecureString secret,
            ISigningAlgorithm signingAlgorithm,
            INonceGenerator nonceGenerator = null,
            ITime time = null)
            : base(innerHandler)
        {
            this.client = client;
            this.secret = secret;
            this.signingAlgorithm = signingAlgorithm;
            this.nonceGenerator = nonceGenerator ?? GuidNonceGenerator.Instance;
            this.time = time ?? SystemTime.Instance;
        }

        protected override HttpRequestMessage ProcessRequest(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var nonce = nonceGenerator.NextNonce();
            var timestamp = time.UtcNow;

            var builder = new CannonicalRepresentationBuilder();
            var content = builder.BuildRepresentation(
                nonce,
                client,
                request.Method.Method,
                request.Content?.Headers?.ContentType?.ToString(),
                request.Headers.Accept.Select(x => x.ToString()).ToArray(),
                request.Content?.Headers?.ContentMD5,
                timestamp,
                request.RequestUri);

            var signature = signingAlgorithm.Sign(secret, Encoding.UTF8.GetBytes(content));

            request.Headers.Authorization = new AuthenticationHeaderValue(Schemas.Bearer, Convert.ToBase64String(signature));
            request.Headers.Add(Headers.XClient, client);
            request.Headers.Add(Headers.XNonce, nonce);
            request.Headers.Date = timestamp;

            return request;
        }

        protected override HttpResponseMessage ProcessResponse(HttpResponseMessage response, CancellationToken cancellationToken) => response;
    }
}