namespace Vrnz2.Security.Helpers.TokenHelper
{
    public interface ITokenHelper
    {
        string GetClaimValue(string requestToken, string claimName);
    }
}
