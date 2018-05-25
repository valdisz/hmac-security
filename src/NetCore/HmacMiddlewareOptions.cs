namespace Security.HMAC
{
    using System;

    public class HmacMiddlewareOptions
    {
        public TimeSpan ClockSkew { get; set; }
    }
}