using Vrnz2.Infra.CrossCutting.Extensions;
using Vrnz2.Security.AppSettings;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Vrnz2.Security.Types
{
    public struct JwtToken
    {
        #region Atributes

        public string OriginalValue { get; private set; }

        public string Value { get; private set; }

        public bool IsValid { get; private set; }

        public bool IsJwtToken { get; private set; }

        public DateTimeOffset? ExpirationDate { get; private set; }

        public Dictionary<string, string> Claims { get; private set; }

        #endregion

        #region Constructors

        public JwtToken(Dictionary<string, string> claimsData, string signingKey)
            : this()
            => IsValid = JwtIsValid(CreateToken(claimsData, signingKey).Value, signingKey);

        public JwtToken(string token, string signingKey)
            : this()
            => IsValid = JwtIsValid(token, signingKey);

        #endregion

        #region Operator

        public static implicit operator JwtToken((Dictionary<string, string> ClaimsData, string SigningKey) param)
            => new JwtToken(param.ClaimsData, param.SigningKey);

        public static implicit operator JwtToken((string Token, string SigningKey) param)
            => new JwtToken(param.Token, param.SigningKey);

        #endregion

        #region Methods

        public bool IsEmpty()
            => string.IsNullOrWhiteSpace(Value);

        public bool IsNull()
            => Value.IsNull();

        public T GetClaimValue<T>(string claimName)
        {
            if (!IsValid)
                return default(T);

            var claimValue = new JwtSecurityTokenHandler()
                .ReadJwtToken(OriginalValue)
                .Claims
                .FirstOrDefault(c => c.Type.Equals(claimName))?
                .Value;

            if (string.IsNullOrWhiteSpace(claimValue))
                return default;
            else
                return JsonConvert.DeserializeObject<T>(claimName);
        }

        public static JwtToken CopyJwt(JwtToken token, string signingKey, Dictionary<string, string> newClaims = null)
        {
            var claims = new List<Claim>();

            JwtToken originalToken = (token.Value, signingKey);

            newClaims.SForEach(i =>
            {
                if (originalToken.Claims.TryGetValue(i.Key, out string _))
                    originalToken.Claims[i.Key] = i.Value;
                else
                    originalToken.Claims.Add(i.Key, i.Value);
            });

            originalToken.Claims.SForEach(claimData => claims.Add(new Claim(claimData.Key, claimData.Value)));

            var tokenConfiguration = new JwtSecurityToken(
                originalToken.Claims[JwtRegisteredClaimNames.Aud],
                originalToken.Claims[JwtRegisteredClaimNames.Iss],
                claims,
                signingCredentials: new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey)), SecurityAlgorithms.HmacSha256),
                expires: DateTime.UtcNow.AddSeconds(SecurityAppSettingsHandler.Instance.SecurityAppSettings.TokenLifetimeInSeconds)
            );

            return (new JwtSecurityTokenHandler().WriteToken(tokenConfiguration), signingKey);
        }

        private JwtToken CreateToken(Dictionary<string, string> claimsData, string signingKey)
        {
            var claims = new List<Claim>();

            var tokenAudience = claimsData.ContainsKey(JwtRegisteredClaimNames.Aud) ? claimsData[JwtRegisteredClaimNames.Aud] : SecurityAppSettingsHandler.Instance.SecurityAppSettings.TokenAudience;
            var tokenIssuer = claimsData.ContainsKey(JwtRegisteredClaimNames.Iss) ? claimsData[JwtRegisteredClaimNames.Iss] : SecurityAppSettingsHandler.Instance.SecurityAppSettings.TokenIssuer;

            claimsData.SForEach(claimData => claims.Add(new Claim(claimData.Key, claimData.Value)));

            var tokenConfiguration = new JwtSecurityToken(
                tokenAudience,
                tokenIssuer,
                claims,
                signingCredentials: new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey)), SecurityAlgorithms.HmacSha256),
                expires: DateTime.UtcNow.AddSeconds(SecurityAppSettingsHandler.Instance.SecurityAppSettings.TokenLifetimeInSeconds)
            );

            return (new JwtSecurityTokenHandler().WriteToken(tokenConfiguration), signingKey);
        }

        private bool JwtIsValid(string token, string signingKey)
        {
            OriginalValue = token;

            var jwtToken = new JwtSecurityTokenHandler().ReadJwtToken(OriginalValue);

            IsJwtToken = jwtToken.IsNotNull();

            IsValid = IsJwtToken && VerifySignature(token, signingKey);

            IsValid = IsValid && jwtToken.ValidFrom <= DateTimeOffset.UtcNow && DateTimeOffset.UtcNow <= jwtToken.ValidTo;

            if (!IsValid) ExpirationDate = jwtToken?.ValidTo;

            Value = OriginalValue;

            var claims = new Dictionary<string, string>();

            jwtToken.Claims.SForEach(c =>
            {
                if (claims.TryGetValue(c.Type, out _))
                    claims[c.Type] = c.Value;
                else
                    claims.Add(c.Type, c.Value);
            });

            Claims = claims;

            return IsValid;
        }

        private bool VerifySignature(string jwtToken, string signingKey)
        {
            string[] parts = jwtToken.Split(".".ToCharArray());
            var header = parts[0];
            var payload = parts[1];
            var signature = parts[2];//Base64UrlEncoded signature from the token

            byte[] bytesToSign = getBytes(string.Join(".", header, payload));

            byte[] secret = getBytes(signingKey);

            var alg = new HMACSHA256(secret);
            var hash = alg.ComputeHash(bytesToSign);

            var computedSignature = Base64UrlEncode(hash);

            return signature.Equals(computedSignature);
        }

        private static byte[] getBytes(string value)
            => Encoding.UTF8.GetBytes(value);

        // from JWT spec
        private static string Base64UrlEncode(byte[] input)
        {
            var output = Convert.ToBase64String(input);
            output = output.Split('=')[0]; // Remove any trailing '='s
            output = output.Replace('+', '-'); // 62nd char of encoding
            output = output.Replace('/', '_'); // 63rd char of encoding
            return output;
        }

        #endregion
    }
}
