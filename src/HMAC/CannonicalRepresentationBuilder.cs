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
            byte[] contentMD5,
            DateTimeOffset time,
            Uri uri)
        {
            string[] content =
            {
                nonce,
                appId,
                method,
                contentType,
                time.ToUniversalTime().ToUnixTimeSeconds().ToString(),
                uri.ToString().ToLowerInvariant()
            };

            if (content.Any(string.IsNullOrWhiteSpace))
            {
                return null;
            }

            string md5 = Convert.ToBase64String(contentMD5);
            return string.Join("|", content) + $"|{md5}";
        }
    }
}