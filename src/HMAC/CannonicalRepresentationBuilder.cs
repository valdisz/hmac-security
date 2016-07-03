namespace Security.HMAC
{
    using System;
    using System.Linq;

    internal sealed class CannonicalRepresentationBuilder
    {
        private static readonly DateTimeOffset dt = new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero);

        public string BuildRepresentation(
            string nonce,
            string appId,
            string method,
            string contentType,
            byte[] contentMD5,
            DateTimeOffset date,
            Uri uri)
        {
            string[] content =
            {
                nonce,
                appId,
                method,
                contentType,
                Convert.ToInt64(date.Subtract(dt).TotalSeconds).ToString(),
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