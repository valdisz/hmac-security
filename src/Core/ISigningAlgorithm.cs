namespace Security.HMAC
{
    using System.Security;

    public interface ISigningAlgorithm
    {
        byte[] Sign(SecureString secret, byte[] content);

        bool Verify(SecureString secret, byte[] content, byte[] signature);
    }
}