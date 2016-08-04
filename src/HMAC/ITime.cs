using System;

namespace Security.HMAC
{
    public interface ITime
    {
        DateTimeOffset UtcNow { get; }
    }
}