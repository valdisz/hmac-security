namespace Security.HMAC
{
    using System;

    public class HmacMiddlewareOptions
    {
        public IAppSecretRepository AppSecretRepository { get; set; }
        public ISigningAlgorithm Algorithm { get; set; }
        public TimeSpan Tolerance { get; set; } = Constants.DefaultTolerance;
        public ITime Time { get; set; } = SystemTime.Instance;
        public MapUserClaimsDelegate MapUserClaims { get; set; }

        public HmacMiddlewareOptions(IAppSecretRepository appSecretRepository, ISigningAlgorithm algorithm)
        {
            AppSecretRepository = appSecretRepository;
            Algorithm = algorithm;
        }
    }
}