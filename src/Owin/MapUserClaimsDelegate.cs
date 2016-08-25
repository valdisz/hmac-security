namespace Security.HMAC
{
    using System.Security.Claims;
    using Microsoft.Owin;

    public delegate Claim[] MapUserClaimsDelegate(string appId, IOwinRequest request);
}