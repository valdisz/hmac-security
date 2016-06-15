namespace Security.HMAC
{
    using System;
    using System.Collections.Generic;
    using Microsoft.Owin;

    internal sealed class Challenger
    {
        private readonly IOwinRequest request;
        private readonly IOwinResponse response;

        public bool Challenged { get; private set; }

        public Challenger(IOwinRequest request, IOwinResponse response)
        {
            this.request = request;
            this.response = response;
        }

        public void Unless(bool condition)
        {
            Challenged |= !condition;
        }

        public void When(bool condition)
        {
            Challenged |= condition;
        }

        public string HeaderValue(string name)
        {
            if (!request.Headers.ContainsKey(name))
            {
                Challenged = true;
                return null;
            }

            return request.Headers[name];
        }

        public IList<string> HeaderValues(string name)
        {
            if (!request.Headers.ContainsKey(name))
            {
                Challenged = true;
                return new string[0];
            }

            return request.Headers.GetValues(name);
        }

        public void WriteChallengeResponse()
        {
            response.StatusCode = 401;
            response.Headers.Append("WWW-Authenticate", HmacMiddleware.Schema);
        }
    }
}