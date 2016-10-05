# hmac-security
Implementation of HMAC based authentication for WebAPI and OWIN


## Usage

### `HttpClient`

```c#
string appId = "your application ID";
SecureString secret = "your application SECRET".ToSecureString();
HmacSigningAlgorithm alogrithm = new HmacSigningAlgorithm(sb => new HMACSHA256(sb));

using (HmacClientHandler hmacHandler = new HMACClientHandler(appId, secret, alogrithm))
using (HttpClient client = new HttpClient(hmacHandler))
{
    await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, "http://localhost/foo"));
}
```


### OWIN

```c#
HmacSigningAlgorithm alogrithm = new HmacSigningAlgorithm(sb => new HMACSHA256(sb));
IAppSecretRepository secretRepo = ...;

app.UseHmacAuthentication(new HmacAuthenticationOptions(alogrithm, secretRepo));
```
