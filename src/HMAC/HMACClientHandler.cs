namespace Security.HMAC
{
    using System;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Security;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;

    public sealed class HMACClientHandler : HttpClientHandler
    {
        private readonly string appId;
        private readonly SecureString secret;
        private readonly ISigningAlgorithm signingAlgorithm;

        public HMACClientHandler(string appId, SecureString secret, ISigningAlgorithm signingAlgorithm)
        {
            this.appId = appId;
            this.secret = secret;
            this.signingAlgorithm = signingAlgorithm;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var nonce = Guid.NewGuid().ToString("N");

            var builder = new CannonicalRepresentationBuilder();
            var content = builder.BuildRepresentation(
                nonce,
                appId,
                request.Method.Method,
                request.Content.Headers.ContentType.MediaType,
                Encoding.UTF8.GetString(request.Content.Headers.ContentMD5),
                request.RequestUri);

            var signature = signingAlgorithm.Sign(secret, content);

            request.Headers.Authorization = new AuthenticationHeaderValue(Schemas.HMAC, signature);
            request.Headers.Add(Headers.XAppId, appId);
            request.Headers.Add(Headers.XNonce, nonce);

            return base.SendAsync(request, cancellationToken);
        }
    }
}