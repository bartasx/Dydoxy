using Microsoft.AspNetCore.Components.Authorization;
using ProxyManagement.Shared.Kernel.Results;

namespace ProxyManagement.BlazorServer.Services.Authentication;

public class AuthenticationService : IAuthenticationService
{
    private readonly CustomAuthenticationStateProvider _authStateProvider;
    private readonly ITokenService _tokenService;
    private readonly ILogger<AuthenticationService> _logger;
    // TODO: Add HTTP client for authentication API when backend is ready
    // private readonly IAuthenticationApiClient _authApiClient;

    public AuthenticationService(
        AuthenticationStateProvider authStateProvider,
        ITokenService tokenService,
        ILogger<AuthenticationService> logger)
    {
        _authStateProvider = (CustomAuthenticationStateProvider)authStateProvider;
        _tokenService = tokenService;
        _logger = logger;
    }

    public async Task<Result<AuthenticationResult>> AuthenticateAsync(string email, string password)
    {
        try
        {
            // TODO: Replace with actual API call to backend authentication service
            // For now, simulate authentication
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password))
            {
                return Result<AuthenticationResult>.Failure(
                    new ValidationError("Email and password are required"));
            }

            // Simulate API call delay
            await Task.Delay(500);

            // Mock user data - replace with actual API response
            var userInfo = new UserInfo
            {
                Id = Guid.NewGuid(),
                Email = email,
                FirstName = "John",
                LastName = "Doe",
                Roles = email.Contains("admin") ? ["Admin"] : ["User"]
            };

            var token = _tokenService.GenerateToken(userInfo);
            var expiresAt = _tokenService.GetTokenExpiration(token);

            var success = await _authStateProvider.LoginAsync(email, password);
            if (!success)
            {
                return Result<AuthenticationResult>.Failure(
                    new BusinessRuleError("Authentication failed"));
            }

            var result = new AuthenticationResult(token, userInfo, expiresAt);
            return Result<AuthenticationResult>.Success(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during authentication for user {Email}", email);
            return Result<AuthenticationResult>.Failure(
                new SystemError("An error occurred during authentication"));
        }
    }

    public async Task<Result> LogoutAsync()
    {
        try
        {
            await _authStateProvider.LogoutAsync();
            return Result.Success();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during logout");
            return Result.Failure(new SystemError("An error occurred during logout"));
        }
    }

    public async Task<Result<UserInfo>> GetCurrentUserAsync()
    {
        try
        {
            var user = await _authStateProvider.GetCurrentUserAsync();
            if (user == null)
            {
                return Result<UserInfo>.Failure(new NotFoundError("User", "current"));
            }

            return Result<UserInfo>.Success(user);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting current user");
            return Result<UserInfo>.Failure(new SystemError("An error occurred getting current user"));
        }
    }

    public async Task<Result> RefreshTokenAsync()
    {
        try
        {
            // TODO: Implement token refresh logic when backend is ready
            await Task.CompletedTask;
            return Result.Success();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error refreshing token");
            return Result.Failure(new SystemError("An error occurred refreshing token"));
        }
    }
}

// Additional error types for authentication
public record ValidationError(string Message) : Error(Message, "VALIDATION_ERROR");
public record BusinessRuleError(string Rule) : Error($"Business rule violation: {Rule}", "BUSINESS_RULE_ERROR");
public record SystemError(string Message) : Error(Message, "SYSTEM_ERROR");
public record NotFoundError(string Resource, string Id) : Error($"{Resource} with id {Id} not found", "NOT_FOUND");