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

        private const string SigningKey = "SecR3t_JWT_OhYeah!@!";

        #endregion 

        #region Methods

        [Fact]
        public void CopyJwt_When_PassingAExistingJwtToken_Should_GetAValidNewJwtToken()
        {
            JwtToken param = (
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJIaXBzdGVyIEUyRSBUZXN0aW5nIFVzZXIiLCJqdGkiOiJhMjliN2Q1NjUzYWY0ZmQyOTY3YjA2M2I0MjYwMWVjMiIsIlVzZXJJZCI6IjQwODgxNzYiLCJJZE1haW4iOiIxODA0MTYwIiwiVXNlclR5cGUiOiIwIiwiVGltZVpvbmUiOiJBbWVyaWNhL1Nhb19QYXVsbyIsIkxvY2FsZSI6InB0LUJSIiwiZXhwIjoxNjM1NTE5OTMwLCJpc3MiOiJNRVdFQl9UUlVOSyIsImF1ZCI6Ik1FV2ViIn0.PAtH1vyTmyneipGhoXoKUWI5tzq0aZ07yJnyXp40jGM",
                SigningKey);
            var token = JwtToken.CopyJwt(param, SigningKey, new Dictionary<string, string> { { JwtRegisteredClaimNamesExtended.UserId, "WFNBR_SEDE" } });

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
                { JwtRegisteredClaimNames.Sub, "MAG Worker Execution" },
                { JwtRegisteredClaimNames.Iss, "MAG Worker" },
                { JwtRegisteredClaimNames.Aud, "MEWEB_TRUNK" },
                { JwtRegisteredClaimNamesExtended.UserId, "1732437" },
                { JwtRegisteredClaimNamesExtended.IdMain, "1578459" },
                { JwtRegisteredClaimNamesExtended.UserType, "0" },
                { JwtRegisteredClaimNamesExtended.TimeZone, "America/Sao_Paulo" },
                { JwtRegisteredClaimNamesExtended.Locale, "pt-BR" }
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
