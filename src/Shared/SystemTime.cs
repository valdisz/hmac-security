namespace Security.HMAC
{
    using System;

    internal class SystemTime : ITime
    {
        public static readonly ITime Instance = new SystemTime();

        public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
    }
}