using System.Security.Claims;

namespace ProxyManagement.BlazorServer.Services.Authentication;

public interface ITokenService
{
    string GenerateToken(UserInfo userInfo);
    bool IsTokenExpired(string token);
    IEnumerable<Claim> GetClaimsFromToken(string token);
    DateTime GetTokenExpiration(string token);
}