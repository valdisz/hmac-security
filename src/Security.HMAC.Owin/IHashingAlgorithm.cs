namespace Security.HMAC
{
    using System.IO;

    public interface IHashingAlgorithm
    {
        byte[] ComputeHash(Stream content);
    }
}