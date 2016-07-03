namespace Security.HMAC
{
    using System;
    using System.Linq;

    public class CannonicalRepresentationBuilder
    {
        public string BuildRepresentation(
            string nonce,
            string appId,
            string method,
            string contentType,
            string contentMD5,
            Uri uri)
        {
            string[] content =
            {
                nonce,
                appId,
                method,
                contentType,
                uri.ToString().ToLowerInvariant()
            };

            if (content.Any(string.IsNullOrWhiteSpace))
            {
                return null;
            }

            return string.Join("|", content) + $"|{contentMD5}";
        }
    }
}