namespace Security.HMAC
{
    using System;

    public class HmacMiddlewareOptions
    {
        public IAppSecretRepository AppSecretRepository { get; set; }
        public ISigningAlgorithm SigningAlgorithm { get; set; }
        public TimeSpan? Tolerance { get; set; }
        public ITime Time { get; set; }
        public MapUserClaimsDelegate MapUserClaims { get; set; }

        public HmacMiddlewareOptions(IAppSecretRepository appSecretRepository, ISigningAlgorithm signingAlgorithm)
        {
            AppSecretRepository = appSecretRepository;
            SigningAlgorithm = signingAlgorithm;
        }
    }
}