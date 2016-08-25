namespace Security.HMAC
{
    using System;

    public sealed class CannonicalRepresentationBuilder
    {
        public string BuildRepresentation(
            string nonce,
            string appId,
            string method,
            string contentType,
            string accepts,
            byte[] contentMD5,
            DateTimeOffset date,
            Uri uri)
        {
            if (nonce == null) throw new ArgumentNullException(nameof(nonce));
            if (appId == null) throw new ArgumentNullException(nameof(appId));
            if (method == null) throw new ArgumentNullException(nameof(method));

            string[] content =
            {
                nonce,
                appId,
                method,
                contentType,
                accepts,
                Convert.ToInt64(date.Subtract(Constants.UnixEpoch).TotalSeconds).ToString(),
                uri.ToString().ToLowerInvariant()
            };

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