namespace Security.HMAC
{
    using System;
    using System.Security;
    using System.Security.Cryptography;
    using System.Text;

    public sealed class HMAC256SigningAlgorith : ISigningAlgorithm
    {
        public static readonly ISigningAlgorithm Instance = new HMAC256SigningAlgorith();

        public string Sign(SecureString secret, string content)
        {
            byte[] contentBytes = Encoding.UTF8.GetBytes(content);
            byte[] secretBytes = secret.ToByteArray(Encoding.UTF8);

            byte[] signatureBytes;
            using (var hmac = new HMACSHA256(secretBytes))
            {
                signatureBytes = hmac.ComputeHash(contentBytes);
            }

            // we need to remove unencrypted secret from memory
            Array.Clear(secretBytes, 0, secretBytes.Length);

            return Convert.ToBase64String(signatureBytes);
        }
    }
}