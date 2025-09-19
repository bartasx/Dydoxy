using ProxyManagement.Shared.Kernel.Results;

namespace ProxyManagement.BlazorServer.Services.Authentication;

public interface IAuthenticationService
{
    Task<Result<AuthenticationResult>> AuthenticateAsync(string email, string password);
    Task<Result> LogoutAsync();
    Task<Result<UserInfo>> GetCurrentUserAsync();
    Task<Result> RefreshTokenAsync();
}

public record AuthenticationResult(
    string Token,
    UserInfo User,
    DateTime ExpiresAt
);