namespace Tests
{
    using System.Security;
    using System.Security.Cryptography;
    using Security.HMAC;
    using Xunit;

    public class Hmac256SigningAlgorithmFacts
    {
        [Fact]
        public void signing_the_same_content_with_the_same_key_produces_identical_results()
        {
            const string content = "qwerty123";
            SecureString secret = "foobar".ToSecureString();
            HmacSigningAlgorithm a1 = new HmacSigningAlgorithm(sb => new HMACSHA256(sb));
            HmacSigningAlgorithm a2 = new HmacSigningAlgorithm(sb => new HMACSHA256(sb));

            var sign1 = a1.Sign(secret, content);
            var sign2 = a2.Sign(secret, content);

            Assert.Equal(sign1, sign2);
        }
    }
}
