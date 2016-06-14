namespace Security.HMAC
{
    using System.Security.Cryptography;

    public class Hmac256SigningAlgorith : ISigningAlgorithm
    {
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