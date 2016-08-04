namespace Security.HMAC
{
    using System.Security;

    public interface IAppSecretRepository
    {
        SecureString GetSecret(string appId);
    }
}