namespace Security.HMAC
{
    using System.IO;
    using System.Security.Cryptography;

    public sealed class Sha256HashingAlgorithm : IHashingAlgorithm
    {
        public static Sha256HashingAlgorithm Instance = new Sha256HashingAlgorithm();

        public byte[] ComputeHash(Stream content)
        {
            long pos = content.Position;
            content.Position = 0;

            byte[] hashBytes;
            using (SHA256Managed sha = new SHA256Managed())
            {
                hashBytes = sha.ComputeHash(content);
            }

            content.Position = pos;

            return hashBytes;
        }
    }
}