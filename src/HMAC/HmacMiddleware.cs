namespace Security.HMAC
{
    using System.Security;
    using System.Threading.Tasks;
    using Microsoft.Owin;

    public class HMACMiddleware : OwinMiddleware
    {
        private readonly IAppSecretRepository appSecretRepository;
        private readonly ISigningAlgorithm signingAlgorithm;

        public HMACMiddleware(
            IAppSecretRepository appSecretRepository,
            ISigningAlgorithm signingAlgorithm,
            OwinMiddleware next) : base(next)
        {
            this.appSecretRepository = appSecretRepository;
            this.signingAlgorithm = signingAlgorithm;
        }

        public override async Task Invoke(IOwinContext context)
        {
            var req = context.Request;
            var res = context.Response;
            var h = req.Headers;

            var appId = h.Get(Headers.XAppId);
            var auth = h.Get(Headers.Authorization)?.Split(' ');
            var authSchema = auth?.Length == 2 ? auth[0] : null;
            var authValue = auth?.Length == 2 ? auth[1] : null;

            if (appId != null && authSchema == Schemas.HMAC && authValue != null)
            {
                var builder = new CannonicalRepresentationBuilder();
                var content = builder.BuildRepresentation(
                    h.Get(Headers.XNonce),
                    appId,
                    req.Method,
                    req.ContentType,
                    h.Get(Headers.ContentMD5),
                    req.Uri);

                SecureString secret;
                if (content != null && (secret = appSecretRepository.GetSecret(appId)) != null)
                {
                    var signature = signingAlgorithm.Sign(secret, content);
                    if (authValue == signature)
                    {
                        await Next.Invoke(context);
                        return;
                    }
                }
            }

            res.StatusCode = 401;
            res.Headers.Append(Headers.WWWAuthenticate, Schemas.HMAC);
        }
    }
}
