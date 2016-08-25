namespace Security.HMAC
{
    using System;
    using System.Security;
    using System.Threading.Tasks;
    using Microsoft.Owin;

    public class HmacMiddleware : OwinMiddleware
    {
        private readonly HmacMiddlewareOptions options;

        public HmacMiddleware(OwinMiddleware next, HmacMiddlewareOptions options)
            : base(next)
        {
            this.options = options;
        }

        public override async Task Invoke(IOwinContext context)
        {
            if (RequestTools.Validate(
                context.Request,
                options.Algorithm,
                options.AppSecretRepository,
                options.Time,
                options.Tolerance))
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
