using Microsoft.IdentityModel.Tokens;

namespace Vrnz2.Security.AppSettings
{
    public class SecurityAppSettings
    {
        public string TokenSubject { get; set; }
        public string TokenIssuer { get; set; }
        public string TokenAudience { get; set; }
        public int TokenLifetimeInSeconds { get; set; }
        public ExtendedSecurityAppSettings ExtendedSettings { get; set; }
        public string SigningKey { get; set; }
        public SecurityKey SecurityKey { get; set; }
        public SigningCredentials SigningCredentials { get; set; }
    }
}
