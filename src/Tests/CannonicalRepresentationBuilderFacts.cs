using System;

namespace Tests
{
    using System.Security.Cryptography;
    using System.Text;
    using Security.HMAC;
    using Xunit;

    public class CannonicalRepresentationBuilderFacts
    {
        static DateTimeOffset dt = new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero);

        [Fact]
        public void representation_is_ordered_correctly()
        {
            CannonicalRepresentationBuilder builder = new CannonicalRepresentationBuilder();

            var date = new DateTimeOffset(2016, 1, 1, 1, 1, 1, 1, TimeSpan.Zero);
            var ticks = Convert.ToInt64(date.Subtract(dt).TotalSeconds).ToString();
            var host = new Uri("http://localhost");

            var repr = builder.BuildRepresentation("none", "appid", "method", "ct", null, date, host);

            Assert.Equal($"none|appid|method|ct|{ticks}|{host.ToString().ToLowerInvariant()}", repr);
        }

        [Fact]
        public void content_hash_is_added_to_representation_only_if_it_present()
        {
            CannonicalRepresentationBuilder builder = new CannonicalRepresentationBuilder();

            var date = new DateTimeOffset(2016, 1, 1, 1, 1, 1, 1, TimeSpan.Zero);
            var ticks = Convert.ToInt64(date.Subtract(dt).TotalSeconds).ToString();
            var host = new Uri("http://localhost");

            byte[] hash;
            using (var md5 = MD5.Create())
            {
                hash = md5.ComputeHash(Encoding.UTF8.GetBytes("foobar"));
            }

            var repr1 = builder.BuildRepresentation("none", "appid", "method", "ct", null, date, host);
            var repr2 = builder.BuildRepresentation("none", "appid", "method", "ct", hash, date, host);

            Assert.True(repr2.Length > repr1.Length);
        }
    }
}
