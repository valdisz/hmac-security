namespace Tests
{
    using System.Runtime.Remoting;
    using System.Security;
    using System.Text;
    using Security.HMAC;
    using Xunit;

    public class SecureStringFacts
    {
        [Fact]
        public void converting_from_to_secure_string_produces_correct_results()
        {
            var encoding = Encoding.UTF8;
            string unsecure = "bar";
            byte[] unsecBytes = encoding.GetBytes(unsecure);

            SecureString secure = unsecure.ToSecureString();

            var secBytes = secure.ToByteArray(encoding);

            Assert.Equal(true, MemTools.Equals(unsecBytes, secBytes));
        }
    }
}
