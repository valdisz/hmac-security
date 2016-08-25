namespace Security.HMAC
{
    using System;
    using Microsoft.Owin.Security;

    public class HmacAuthenticationOptions : AuthenticationOptions
    {
        public HmacAuthenticationOptions()
            : base(Schemas.HMAC)
        {
        }

        public ISigningAlgorithm Algorithm { get; set; }
        public IAppSecretRepository AppSecretRepository { get; set; }
        public ITime Time { get; set; } = SystemTime.Instance;
        public TimeSpan Tolerance { get; set; } = Constants.DefaultTolerance;
        public MapUserClaimsDelegate MapClaims { get; set; }
    }
}