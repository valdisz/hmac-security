namespace Tests
{
    using System.Linq;
    using System.Net.Http;
    using System.Security;
    using System.Security.Cryptography;
    using System.Threading;
    using System.Threading.Tasks;
    using Security.HMAC;
    using Xunit;

    public class InspectionMessageHandler : HttpMessageHandler
    {
        public HttpRequestMessage LastRequest { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;

            var responseTask = new TaskCompletionSource<HttpResponseMessage>();
            responseTask.SetResult(new HttpResponseMessage());

            return responseTask.Task;
        }
    }

    public class HmacClientHandlerFacts
    {
        private const string appId = "app";
        private static readonly SecureString secret = "qwerty".ToSecureString();

        [Fact]
        public async void custom_headers_are_added_to_request()
        {
            using (InspectionMessageHandler inspector = new InspectionMessageHandler())
            using (HmacClientHandler hmacHandler = new HmacClientHandler(inspector, appId, secret, new HmacSigningAlgorithm(sb => new HMACSHA256(sb))))
            using (HttpClient client = new HttpClient(hmacHandler))
            {
                await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, "http://localhost/foo"));

                var req = inspector.LastRequest;

                Assert.Equal(appId, req.Headers.GetValues(Headers.XClient).First());
                Assert.False(string.IsNullOrWhiteSpace(req.Headers.GetValues(Headers.XNonce).FirstOrDefault()));
            }
        }

        [Fact]
        public async void authorization_header_is_set_with_correct_schema()
        {
            using (InspectionMessageHandler inspector = new InspectionMessageHandler())
            using (HmacClientHandler hmacHandler = new HmacClientHandler(inspector, appId, secret, new HmacSigningAlgorithm(sb => new HMACSHA256(sb))))
            using (HttpClient client = new HttpClient(hmacHandler))
            {
                await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, "http://localhost/foo"));

                var req = inspector.LastRequest;

                Assert.Equal(Schemas.HMAC, req.Headers.Authorization.Scheme);
            }
        }

        [Fact]
        public async void authorization_header_parameter_is_not_null()
        {
            using (InspectionMessageHandler inspector = new InspectionMessageHandler())
            using (HmacClientHandler hmacHandler = new HmacClientHandler(inspector, appId, secret, new HmacSigningAlgorithm(sb => new HMACSHA256(sb))))
            using (HttpClient client = new HttpClient(hmacHandler))
            {
                await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, "http://localhost/foo"));

                var req = inspector.LastRequest;

                Assert.False(string.IsNullOrWhiteSpace(req.Headers.Authorization.Parameter));
            }
        }
    }
}