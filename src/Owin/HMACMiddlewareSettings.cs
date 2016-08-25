namespace Security.HMAC
{
    using System;

    public class HMACMiddlewareSettings
    {
        public IAppSecretRepository AppSecretRepository { get; set; }
        public ISigningAlgorithm SigningAlgorithm { get; set; }
        public TimeSpan? Tolerance { get; set; }
        public ITime Time { get; set; }
        public MapUserClaimsDelegate MapUserClaims { get; set; }

        public HMACMiddlewareSettings(IAppSecretRepository appSecretRepository, ISigningAlgorithm signingAlgorithm)
        {
            AppSecretRepository = appSecretRepository;
            SigningAlgorithm = signingAlgorithm;
        }
    }
}