# hmac-security
Implementation of HMAC based authentication for WebAPI and OWIN


## Usage

On `HttpClient`:

```c#
string appId = "your application ID";
SecureString secret = "your application SECRET".ToSecureString();
HmacSigningAlgorithm alogrithm = new HmacSigningAlgorithm(sb => new HMACSHA256(sb))

using (HmacClientHandler hmacHandler = new HMACClientHandler(inspector, appId, secret, alogrithm))
using (HttpClient client = new HttpClient(hmacHandler))
{
    await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, "http://localhost/foo"));
}
```