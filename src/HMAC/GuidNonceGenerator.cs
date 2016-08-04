namespace Security.HMAC
{
    using System;

    internal class GuidNonceGenerator : INonceGenerator
    {
        public static readonly INonceGenerator Instance = new GuidNonceGenerator();

        public string NextNonce => Guid.NewGuid().ToString("N");
    }
}