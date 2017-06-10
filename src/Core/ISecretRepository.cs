namespace Security.HMAC
{
    using System.Security;

    public interface ISecretRepository
    {
        SecureString GetSecret(string client);
    }
}