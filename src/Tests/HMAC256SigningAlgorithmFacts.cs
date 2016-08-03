namespace Tests
{
    using System.Security;
    using Security.HMAC;
    using Xunit;

    public class HMAC256SigningAlgorithmFacts
    {
        [Fact]
        public void signing_the_same_content_with_the_same_key_produces_identical_results()
        {
            const string content = "qwerty123";
            SecureString secret = "foobar".ToSecureString();
            HMAC256SigningAlgorithm a1 = new HMAC256SigningAlgorithm();
            HMAC256SigningAlgorithm a2 = new HMAC256SigningAlgorithm();

            var sign1 = a1.Sign(secret, content);
            var sign2 = a2.Sign(secret, content);

            Assert.Equal(sign1, sign2);
        }
    }
}
