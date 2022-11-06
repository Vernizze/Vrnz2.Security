using FluentAssertions;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using Vrnz2.Security.Types;
using Xunit;

namespace Vrnz2.Security.Tests.Types
{
    public class JwtTest
    {
        #region Constants

        private const string SigningKey = "F01OGKYB6RLGEB47YYBU";

        #endregion 

        #region Methods

        [Fact]
        public void CopyJwt_When_PassingAExistingJwtToken_Should_GetAValidNewJwtToken()
        {
            JwtToken param = (
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJJbmNsdXNpb24gU2NvcmUgQVBJIiwiaXNzIjoiVnJuejIiLCJhdWQiOlsiVnJuejIiLCJWcm56MiBBdXRoIl0sImV4cCI6MTY2Nzc1OTI2MH0.N7cqGtGwHDMjgnSwEx25Ay12JzF5n-GMpaNa81sl7Os",
                SigningKey);
            var token = JwtToken.CopyJwt(param, SigningKey, new Dictionary<string, string> { { "Teste", "Valor Teste" } });

            JwtToken xablau = (token.Claims, SigningKey);

            token.Should().NotBeNull();
            token.IsValid.Should().BeTrue();
        }

        [Fact]
        public void ValidPwd_StringValue_Valid()
        {
            // Arrange
            var claims = new Dictionary<string, string>()
            {
                { JwtRegisteredClaimNames.Sub, "Inclusion Score API" },
                { JwtRegisteredClaimNames.Iss, "Vrnz2 Auth" },
                { JwtRegisteredClaimNames.Aud, "Vrnz2" }
            };

            // Act
            JwtToken token = new JwtToken(claims, SigningKey);

            // Assert
            token.Should().NotBeNull();
            token.IsValid.Should().BeTrue();
        }

        #endregion
    }
}
