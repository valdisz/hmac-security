namespace Security.HMAC
{
    using System;

    internal static class Constants
    {
        public static readonly TimeSpan DefaultTolerance = TimeSpan.FromSeconds(3);

        public static readonly DateTimeOffset UnixEpoch = new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero);
    }
}