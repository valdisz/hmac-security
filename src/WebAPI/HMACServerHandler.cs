namespace Security.HMAC
{
    using System;
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Security;
    using System.Threading;
    using System.Threading.Tasks;

    public class HMACServerHandler : DelegatingHandler
    {
        private readonly TimeSpan tolerance;
        private readonly IAppSecretRepository appSecretRepository;
        private readonly ISigningAlgorithm signingAlgorithm;
        private readonly ITime time;

        public HMACServerHandler(
            HttpMessageHandler innerHandler,
            IAppSecretRepository appSecretRepository,
            ISigningAlgorithm signingAlgorithm,
            TimeSpan? tolerance = null,
            ITime time = null)
            : base(innerHandler)
        {
            this.appSecretRepository = appSecretRepository;
            this.signingAlgorithm = signingAlgorithm;
            this.tolerance = tolerance ?? Constants.DefaultTolerance;
            this.time = time ?? SystemTime.Instance;
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var req = request;
            var h = req.Headers;

            var appId = h.GetValues(Headers.XAppId).First();
            var authSchema = h.Authorization?.Scheme;
            var authValue = h.Authorization?.Parameter;
            var date = h.Date ?? DateTimeOffset.MinValue;

            if (appId != null
                && authSchema == Schemas.HMAC
                && authValue != null
                && time.UtcNow - date <= tolerance)
            {
                var builder = new CannonicalRepresentationBuilder();
                var content = builder.BuildRepresentation(
                    h.GetValues(Headers.XNonce).FirstOrDefault(),
                    appId,
                    req.Method.Method,
                    req.Content.Headers.ContentType.MediaType,
                    string.Join("; ", req.Headers.Accept),
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