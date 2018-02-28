namespace Sable.HMAC
{
    using System;
    using System.Security;
    using System.Security.Cryptography;
    using System.Text;

    public delegate HMAC HmacAlgorithmFactory(byte[] secretBytes);

    public sealed class HmacSigningAlgorithm : ISigningAlgorithm
    {
        private readonly HmacAlgorithmFactory algorithmFactory;

        public HmacSigningAlgorithm(HmacAlgorithmFactory algorithmFactory)
        {
            this.algorithmFactory = algorithmFactory;
        }

        public byte[] Sign(SecureString secret, byte[] content)
        {
            byte[] secretBytes = secret.ToByteArray(Encoding.UTF8);

            byte[] signature;
            using (var hmac = algorithmFactory(secretBytes))
            {
                signature = hmac.ComputeHash(content);
            }

            // we need to remove unencrypted secret from memory
            Array.Clear(secretBytes, 0, secretBytes.Length);

            return signature;
        }

        public bool Verify(SecureString secret, byte[] content, byte[] signature)
        {
            var refSignature = Sign(secret, content);
            return MemTools.Equals(refSignature, signature);
        }
    }
}