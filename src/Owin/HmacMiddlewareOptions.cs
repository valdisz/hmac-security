namespace Security.HMAC
{
    using System;

    public class HmacMiddlewareOptions
    {
        public ISecretRepository SecretRepository { get; set; }
        public ISigningAlgorithm Algorithm { get; set; }
        public TimeSpan ClockSkew { get; set; } = Constants.DefaultClockSkew;
        public ITime Time { get; set; } = SystemTime.Instance;
        public MapUserClaimsDelegate MapUserClaims { get; set; }

        public HmacMiddlewareOptions(ISecretRepository secretRepository, ISigningAlgorithm algorithm)
        {
            SecretRepository = secretRepository;
            Algorithm = algorithm;
        }
    }
}