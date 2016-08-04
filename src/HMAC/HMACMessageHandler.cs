namespace Security.HMAC
{
    using System;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Security;
    using System.Threading;

    public sealed class HMACMessageHandler : MessageProcessingHandler
    {
        private readonly string appId;
        private readonly SecureString secret;
        private readonly ISigningAlgorithm signingAlgorithm;

        public HMACMessageHandler(HttpMessageHandler innerHandler, string appId, SecureString secret, ISigningAlgorithm signingAlgorithm)
            : base(innerHandler)
        {
            this.appId = appId;
            this.secret = secret;
            this.signingAlgorithm = signingAlgorithm;
        }

        protected override HttpRequestMessage ProcessRequest(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var nonce = Guid.NewGuid().ToString("N");
            var time = DateTimeOffset.UtcNow;

            var builder = new CannonicalRepresentationBuilder();
            var content = builder.BuildRepresentation(
                nonce,
                appId,
                request.Method.Method,
                request.Content?.Headers?.ContentType?.MediaType,
                string.Join(";", request.Headers.Accept),
                request.Content?.Headers?.ContentMD5,
                time,
                request.RequestUri);

            var signature = signingAlgorithm.Sign(secret, content);

            request.Headers.Authorization = new AuthenticationHeaderValue(Schemas.HMAC, signature);
            request.Headers.Add(Headers.XAppId, appId);
            request.Headers.Add(Headers.XNonce, nonce);
            request.Headers.Date = time;

            return request;
        }

        protected override HttpResponseMessage ProcessResponse(HttpResponseMessage response, CancellationToken cancellationToken)
        {
            return response;
        }
    }
}