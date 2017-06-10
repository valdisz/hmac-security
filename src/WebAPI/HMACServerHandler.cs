namespace Security.HMAC
{
    using System;
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Security;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;

    public class HmacServerHandler : DelegatingHandler
    {
        private readonly TimeSpan clockSkew;
        private readonly ISecretRepository secretRepository;
        private readonly ISigningAlgorithm signingAlgorithm;
        private readonly ITime time;

        public HmacServerHandler(
            ISecretRepository secretRepository,
            ISigningAlgorithm signingAlgorithm,
            TimeSpan? clockSkew = null,
            ITime time = null)
        {
            this.secretRepository = secretRepository;
            this.signingAlgorithm = signingAlgorithm;
            this.clockSkew = clockSkew ?? Constants.DefaultClockSkew;
            this.time = time ?? SystemTime.Instance;
        }

        public HmacServerHandler(
            HttpMessageHandler innerHandler,
            ISecretRepository secretRepository,
            ISigningAlgorithm signingAlgorithm,
            TimeSpan? clockSkew = null,
            ITime time = null)
            : base(innerHandler)
        {
            this.secretRepository = secretRepository;
            this.signingAlgorithm = signingAlgorithm;
            this.clockSkew = clockSkew ?? Constants.DefaultClockSkew;
            this.time = time ?? SystemTime.Instance;
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var req = request;
            var h = req.Headers;

            var client = h.Contains(Headers.XClient)
                ? h.GetValues(Headers.XClient).FirstOrDefault()
                : null;
            var nonce = h.Contains(Headers.XNonce)
                ? h.GetValues(Headers.XNonce).FirstOrDefault()
                : null;
            var scheme = h.Authorization?.Scheme;
            var token = h.Authorization?.Parameter;
            var date = h.Date ?? DateTimeOffset.MinValue;

            if (
                client != null
                && nonce != null
                && scheme == Schemas.Bearer
                && token != null
                && time.UtcNow - date <= clockSkew)
            {
                var builder = new CannonicalRepresentationBuilder();
                var content = builder.BuildRepresentation(
                    nonce,
                    client,
                    req.Method.Method,
                    req.Content.Headers.ContentType?.ToString(),
                    req.Headers.Accept.Select(x => x.ToString()).ToArray(),
                    req.Content.Headers.ContentMD5,
                    date,
                    req.RequestUri);

                SecureString secret = secretRepository.GetSecret(client);
                if (secret != null)
                {
                    var isTokenValid = signingAlgorithm.Verify(
                        secret,
                        Encoding.UTF8.GetBytes(content),
                        Convert.FromBase64String(token));

                    if (isTokenValid)
                    {
                        return await base.SendAsync(request, cancellationToken);
                    }
                }
            }

            return new HttpResponseMessage(HttpStatusCode.Unauthorized)
            {
                Headers =
                {
                    { Headers.WWWAuthenticate, Schemas.Bearer }
                }
            };
        }
    }
}