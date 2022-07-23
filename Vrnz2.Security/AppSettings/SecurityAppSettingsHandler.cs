using Vrnz2.Infra.CrossCutting.Extensions;
using Vrnz2.Infra.CrossCutting.Utils;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace Vrnz2.Security.AppSettings
{
    public class SecurityAppSettingsHandler
    {
        private static SecurityAppSettingsHandler _instance;

        private SecurityAppSettingsHandler()
        {
            SecurityAppSettings = DependencyInjectionHandler.GetInstance<SecurityAppSettings>();

            if (SecurityAppSettings.IsNull())
                SecurityAppSettings = FilesAndFolders.GetAppSettingsContent<RootSettings>().TokenSettings;

            SecurityAppSettings.SecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecurityAppSettings.SigningKey));

            SecurityAppSettings.SigningCredentials = new SigningCredentials(SecurityAppSettings.SecurityKey, SecurityAlgorithms.HmacSha256);
        }

        public static SecurityAppSettingsHandler Instance
        {
            get
            {
                _instance ??= new SecurityAppSettingsHandler();

                return _instance;
            }
        }

        public SecurityAppSettings SecurityAppSettings { private set; get; }
    }
}
