namespace Sable.HMAC
{
    using System;

    public interface ITime
    {
        DateTimeOffset UtcNow { get; }
    }
}