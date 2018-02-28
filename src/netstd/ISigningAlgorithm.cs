namespace Sable.HMAC
{
    using System.IO;
    using System.Security;

    public interface ISigningAlgorithm
    {
        byte[] Sign(SecureString secret, Stream content);

        bool Verify(SecureString secret, Stream content, byte[] signature);
    }
}