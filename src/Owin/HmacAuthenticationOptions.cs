namespace Security.HMAC
{
    using System;
    using Microsoft.Owin.Security;

    public class HmacAuthenticationOptions : AuthenticationOptions
    {
        public HmacAuthenticationOptions(ISigningAlgorithm algorithm, ISecretRepository secretRepository, string signInAsAuthenticationType = Schemas.HMAC)
            : base(Schemas.HMAC)
        {
            Algorithm = algorithm;
            SecretRepository = secretRepository;
            SignInAsAuthenticationType = signInAsAuthenticationType;
        }

        public ISigningAlgorithm Algorithm { get; set; }
        public ISecretRepository SecretRepository { get; set; }
        public ITime Time { get; set; } = SystemTime.Instance;
        public TimeSpan ClockSkew { get; set; } = Constants.DefaultClockSkew;
        public MapUserClaimsDelegate MapClaims { get; set; }
        public string SignInAsAuthenticationType { get; set; }
    }
}