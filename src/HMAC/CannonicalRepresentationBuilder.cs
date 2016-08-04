namespace Security.HMAC
{
    using System;
    using System.Linq;

    internal sealed class CannonicalRepresentationBuilder
    {
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
                Convert.ToInt64(date.Subtract(Constants.UnixEpoch).TotalSeconds).ToString(),
                uri.ToString().ToLowerInvariant()
            };

            if (content.Any(string.IsNullOrWhiteSpace))
            {
                return null;
            }

            var representation = string.Join("|", content);
            if ((contentMD5?.Length ?? 0) != 0)
            {
                string md5 = Convert.ToBase64String(contentMD5);
                representation += $"|{md5}";
            }

            return representation;
        }
    }
}