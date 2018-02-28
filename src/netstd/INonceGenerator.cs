namespace Sable.HMAC
{
    public interface INonceGenerator
    {
        string NextNonce();
    }
}