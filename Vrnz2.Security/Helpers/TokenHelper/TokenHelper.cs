using Vrnz2.Infra.CrossCutting.Extensions;
using Vrnz2.Security.AppSettings;
using Vrnz2.Security.Types;

namespace Vrnz2.Security.Helpers.TokenHelper
{
    public class TokenHelper
        : ITokenHelper
    {
        #region Methods

        public string GetClaimValue(string requestToken, string claimName)
        {
            JwtToken token = (requestToken, SecurityAppSettingsHandler.Instance.SecurityAppSettings.SigningKey);

            var claimValue = token.Claims.SFirstOrDefault(c => claimName.Equals(c.Key));

            if (claimValue.Key.IsNull() && claimValue.Value.IsNull())
                return string.Empty;

            return claimValue.Value;
        }

        #endregion
    }
}
