namespace Security.HMAC
{
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

        public override Task Invoke(IOwinContext context)
        {
            if (!RequestTools.Validate(
                context.Request,
                options.Algorithm,
                options.SecretRepository,
                options.Time,
                options.ClockSkew))
            {
                var res = context.Response;
                res.StatusCode = 401;
                res.Headers.Append(Headers.WWWAuthenticate, Schemas.Bearer);

                return Task.CompletedTask;
            }

            return Next.Invoke(context);
        }
    }
}
