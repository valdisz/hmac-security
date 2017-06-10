namespace Security.HMAC
{
    public interface INonceGenerator
    {
        string NextNonce();
    }
}