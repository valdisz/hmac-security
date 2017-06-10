namespace Security.HMAC
{
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Microsoft.Owin;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Infrastructure;

    public class HmacAuthenticationHandler : AuthenticationHandler<HmacAuthenticationOptions>
    {

        protected override Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationTicket ticket = null;

            if (RequestTools.Validate(
                Request, 
                Options.Algorithm,
                Options.AppSecretRepository,
                Options.Time,
                Options.ClockSkew))
            {
                var appId = RequestTools.GetClient(Request);

                var claims = MapDefaultClaims(appId, Request);
                if (Options.MapClaims != null)
                {
                    claims = MergeClaims(claims, Options.MapClaims(appId, Request));
                }

                ticket = new AuthenticationTicket(new ClaimsIdentity(claims, Options.SignInAsAuthenticationType), new AuthenticationProperties());
            }

            return Task.FromResult(ticket);
        }

        private static Claim[] MapDefaultClaims(string appId, IOwinRequest request)
        {
            return new[]
            {
                new Claim(ClaimTypes.NameIdentifier, appId)
            };
        }

        private static Claim[] MergeClaims(Claim[] left, Claim[] right)
        {
            HashSet<Claim> claims = new HashSet<Claim>(left);
            claims.ExceptWith(right);
            claims.UnionWith(right);

            return claims.ToArray();
        }
    }
}