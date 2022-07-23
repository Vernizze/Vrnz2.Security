using Microsoft.Extensions.DependencyInjection;
using Vrnz2.Security.AppSettings;

namespace Vrnz2.Security.Extensions
{
    public static class SecurityExtensions
    {
        public static IServiceCollection AddJwtSecurity(this IServiceCollection services, SecurityAppSettings securityAppSettings)
            => services.AddSingleton(_ => securityAppSettings);
    }
}
