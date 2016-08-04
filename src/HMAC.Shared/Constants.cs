namespace Security.HMAC
{
    using System;

    public static class Headers
    {
        public const string Authorization = "Authorization";
        public const string WWWAuthenticate = "WWW-Authenticate";
        public const string ContentMD5 = "Content-MD5";
        public const string Date = "Date";
        public const string XAppId = "X-HMAC-AppId";
        public const string XNonce = "X-HMAC-Nonce";
    }

    public static class Schemas
    {
        public const string HMAC = "HMAC";
    }

    internal static class Constants
    {
        public static readonly TimeSpan DefaultTolerance = TimeSpan.FromSeconds(3);

        public static readonly DateTimeOffset UnixEpoch = new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero);
    }
}