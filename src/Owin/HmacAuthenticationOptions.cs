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
        public ITime Time { get; set; }
        public TimeSpan Tolerance { get; set; }
        public MapUserClaimsDelegate MapClaims { get; set; }
    }
}