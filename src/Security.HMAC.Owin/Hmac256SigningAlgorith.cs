namespace Security.HMAC
{
    using System.Security.Cryptography;

    public sealed class Hmac256SigningAlgorith : ISigningAlgorithm
    {
        public static readonly Hmac256SigningAlgorith Instance = new Hmac256SigningAlgorith();

        public byte[] Sign(byte[] secret, byte[] content)
        {
            byte[] signatureBytes;
            using (var hmac = new HMACSHA256(secret))
            {
                signatureBytes = hmac.ComputeHash(content);
            }

            return signatureBytes;
        }
    }
}