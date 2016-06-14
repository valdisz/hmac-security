namespace Security.HMAC
{
    public interface ISigningAlgorithm
    {
        byte[] Sign(byte[] secret, byte[] content);
    }
}