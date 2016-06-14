namespace Security.HMAC
{
    public interface IAppSecretRepository
    {
        string GetSecret(string appId);
    }
}