namespace Security.HMAC
{
    using System;
    using System.Linq;

    public sealed class CannonicalRepresentationBuilder
    {
        public string BuildRepresentation(
            string nonce,
            string client,
            string method,
            string contentType,
            string[] accepts,
            byte[] contentMD5,
            DateTimeOffset date,
            Uri uri)
        {
            if (nonce == null) throw new ArgumentNullException(nameof(nonce));
            if (client == null) throw new ArgumentNullException(nameof(client));
            if (method == null) throw new ArgumentNullException(nameof(method));

            string[] content =
            {
                nonce,
                client,
                method,
                contentType,
                string.Join("|", accepts.Select(x => x.Trim())),
                date.ToString("R"),
                uri.ToString().ToLowerInvariant(),
                (contentMD5?.Length ?? 0) > 0
                    ? Convert.ToBase64String(contentMD5)
                    : ""
            };

            var representation = string.Join("|", content);

            return representation;
        }
    }
}