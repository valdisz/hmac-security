namespace Security.HMAC
{
    using System.Security;

    public interface ISigningAlgorithm
    {
        string Sign(SecureString secret, string content);
    }
}