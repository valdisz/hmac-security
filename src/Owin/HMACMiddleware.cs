namespace Security.HMAC
{
    using System;
    using System.Security;
    using System.Threading.Tasks;
    using Microsoft.Owin;

    public class HmacMiddleware : OwinMiddleware
    {
        private readonly IAppSecretRepository appSecretRepository;
        private readonly ISigningAlgorithm signingAlgorithm;
        private readonly ITime time;
        private readonly TimeSpan tolerance;

        public HmacMiddleware(OwinMiddleware next, ISigningAlgorithm signingAlgorithm, IAppSecretRepository appSecretRepository, ITime time = null, TimeSpan? tolerance = null)
            : base(next)
        {
            this.appSecretRepository = appSecretRepository;
            this.signingAlgorithm = signingAlgorithm;
            this.tolerance = tolerance ?? Constants.DefaultTolerance;
            this.time = time ?? SystemTime.Instance;
        }

        public override async Task Invoke(IOwinContext context)
        {
            if (RequestTools.Validate(context.Request, signingAlgorithm, appSecretRepository, time, tolerance))
            {
                await Next.Invoke(context);
            }
            else
            {
                var res = context.Response;
                res.StatusCode = 401;
                res.Headers.Append(Headers.WWWAuthenticate, Schemas.HMAC);
            }
        }
    }
}
