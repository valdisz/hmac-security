namespace Security.HMAC
{
    using System;
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Security;
    using System.Threading;
    using System.Threading.Tasks;

    public class HmacServerHandler : DelegatingHandler
    {
        private readonly TimeSpan tolerance;
        private readonly IAppSecretRepository appSecretRepository;
        private readonly ISigningAlgorithm signingAlgorithm;
        private readonly bool mixedAuthMode;
        private readonly ITime time;

        public HmacServerHandler(
            IAppSecretRepository appSecretRepository,
            ISigningAlgorithm signingAlgorithm,
            bool mixedAuthMode = false,
            TimeSpan? tolerance = null,
            ITime time = null)
        {
            this.appSecretRepository = appSecretRepository;
            this.signingAlgorithm = signingAlgorithm;
            this.mixedAuthMode = mixedAuthMode;
            this.tolerance = tolerance ?? Constants.DefaultTolerance;
            this.time = time ?? SystemTime.Instance;
        }

        public HmacServerHandler(
            HttpMessageHandler innerHandler,
            IAppSecretRepository appSecretRepository,
            ISigningAlgorithm signingAlgorithm,
            bool mixedAuthMode = false,
            TimeSpan? tolerance = null,
            ITime time = null)
            : base(innerHandler)
        {
            this.appSecretRepository = appSecretRepository;
            this.signingAlgorithm = signingAlgorithm;
            this.mixedAuthMode = mixedAuthMode;
            this.tolerance = tolerance ?? Constants.DefaultTolerance;
            this.time = time ?? SystemTime.Instance;
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var req = request;
            var h = req.Headers;

            if (mixedAuthMode && h.Authorization?.Scheme != Schemas.HMAC)
            {
                return await base.SendAsync(request, cancellationToken);
            }

            var appId = h.Contains(Headers.XAppId)
                ? h.GetValues(Headers.XAppId).FirstOrDefault()
                : null;
            var authValue = h.Authorization?.Parameter;
            var date = h.Date ?? DateTimeOffset.MinValue;

            if (appId != null
                && authValue != null
                && time.UtcNow - date <= tolerance)
            {
                var builder = new CannonicalRepresentationBuilder();
                var content = builder.BuildRepresentation(
                    h.GetValues(Headers.XNonce).FirstOrDefault(),
                    appId,
                    req.Method.Method,
                    req.Content.Headers.ContentType?.ToString(),
                    string.Join(", ", req.Headers.Accept),
                    req.Content.Headers.ContentMD5,
                    date,
                    req.RequestUri);

                SecureString secret;
                if (content != null && (secret = appSecretRepository.GetSecret(appId)) != null)
                {
                    var signature = signingAlgorithm.Sign(secret, content);
                    if (authValue == signature)
                    {
                        return await base.SendAsync(request, cancellationToken);
                    }
                }
            }

            return new HttpResponseMessage(HttpStatusCode.Unauthorized)
            {
                Headers =
                {
                    { Headers.WWWAuthenticate, Schemas.HMAC }
                }
            };
        }
    }
}