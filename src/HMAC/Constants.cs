namespace Security.HMAC
{
    internal static class Headers
    {
        public const string Authorization = "Authorization";
        public const string WWWAuthenticate = "WWW-Authenticate";
        public const string ContentMD5 = "Content-MD5";
        public const string XAppId = "X-HMAC-AppId";
        public const string XNonce = "X-HMAC-Nonce";
    }

    internal class Schemas
    {
        public const string HMAC = "HMAC";
    }
}