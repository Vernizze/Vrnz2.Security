using Vrnz2.Security.Types;
using Xunit;

namespace Vrnz2.Security.Tests.Types
{
    public class PwdTest
    {
        [Theory]
        [InlineData("#123Abcd")]
        public void ValidPwd_StringValue_Valid(string value)
        {
            Pwd pwd = value;

            Assert.True(pwd.IsValid);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("@1A")]
        [InlineData("2123Abcd")]
        [InlineData("#123A cd")]
        [InlineData("#adadAbcd")]
        [InlineData("#123abcd")]
        public void ValidPwd_StringValue_NotValid(string value)
        {
            Pwd pwd = value;

            Assert.False(pwd.IsValid);
        }

        [Theory]
        [InlineData("#123Abcd", "#123Abcd", "12345678")]
        public void ValidPwd_Compare_Success(string value01, string value02, string salt)
        {
            Pwd pwd01 = value01;
            Pwd pwd02 = value02;

            pwd01.GetHash(salt);
            pwd02.GetHash(salt);

            Assert.Equal(pwd01.Value, pwd02.Value);
        }

        [Theory]
        [InlineData("#123Abcd", "#123Abcd")]
        public void ValidPwd_Compare_Fail(string value01, string value02)
        {
            var salt01 = "12345678";
            var salt02 = "12345679";
            Pwd pwd01 = value01;
            Pwd pwd02 = value02;

            pwd01.GetHash(salt01);
            pwd02.GetHash(salt02);

            Assert.NotEqual(pwd01.Value, pwd02.Value);
        }
    }
}
