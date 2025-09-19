using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using System.Security.Claims;
using System.Text.Json;

namespace ProxyManagement.BlazorServer.Services.Authentication;

public class CustomAuthenticationStateProvider : AuthenticationStateProvider
{
    private readonly ProtectedSessionStorage _sessionStorage;
    private readonly ILogger<CustomAuthenticationStateProvider> _logger;
    private readonly ITokenService _tokenService;

    private const string TokenKey = "authToken";
    private const string UserKey = "currentUser";

    public CustomAuthenticationStateProvider(
        ProtectedSessionStorage sessionStorage,
        ILogger<CustomAuthenticationStateProvider> logger,
        ITokenService tokenService)
    {
        _sessionStorage = sessionStorage;
        _logger = logger;
        _tokenService = tokenService;
    }

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        try
        {
            var tokenResult = await _sessionStorage.GetAsync<string>(TokenKey);
            var userResult = await _sessionStorage.GetAsync<string>(UserKey);

            if (!tokenResult.Success || string.IsNullOrEmpty(tokenResult.Value) ||
                !userResult.Success || string.IsNullOrEmpty(userResult.Value))
            {
                return CreateAnonymousState();
            }

            if (_tokenService.IsTokenExpired(tokenResult.Value))
            {
                await ClearAuthenticationDataAsync();
                return CreateAnonymousState();
            }

            var userInfo = JsonSerializer.Deserialize<UserInfo>(userResult.Value);
            if (userInfo == null)
            {
                return CreateAnonymousState();
            }

            var claims = CreateClaims(userInfo);
            var identity = new ClaimsIdentity(claims, "custom");
            
            return new AuthenticationState(new ClaimsPrincipal(identity));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting authentication state");
            return CreateAnonymousState();
        }
    }

    public async Task<bool> LoginAsync(string email, string password)
    {
        try
        {
            // Here you would typically call your authentication API
            // For now, we'll simulate a successful login
            var userInfo = new UserInfo
            {
                Id = Guid.NewGuid(),
                Email = email,
                FirstName = "John",
                LastName = "Doe",
                Roles = ["User"]
            };

            var token = _tokenService.GenerateToken(userInfo);

            await _sessionStorage.SetAsync(TokenKey, token);
            await _sessionStorage.SetAsync(UserKey, JsonSerializer.Serialize(userInfo));

            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
            
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during login for user {Email}", email);
            return false;
        }
    }

    public async Task LogoutAsync()
    {
        try
        {
            await ClearAuthenticationDataAsync();
            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during logout");
        }
    }

    public async Task<UserInfo?> GetCurrentUserAsync()
    {
        try
        {
            var userResult = await _sessionStorage.GetAsync<string>(UserKey);
            if (!userResult.Success || string.IsNullOrEmpty(userResult.Value))
            {
                return null;
            }

            return JsonSerializer.Deserialize<UserInfo>(userResult.Value);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting current user");
            return null;
        }
    }

    private static AuthenticationState CreateAnonymousState()
    {
        return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
    }

    private static List<Claim> CreateClaims(UserInfo userInfo)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, userInfo.Id.ToString()),
            new(ClaimTypes.Email, userInfo.Email),
            new(ClaimTypes.Name, userInfo.FullName),
            new(ClaimTypes.GivenName, userInfo.FirstName),
            new(ClaimTypes.Surname, userInfo.LastName)
        };

        claims.AddRange(userInfo.Roles.Select(role => new Claim(ClaimTypes.Role, role)));

        return claims;
    }

    private async Task ClearAuthenticationDataAsync()
    {
        await _sessionStorage.DeleteAsync(TokenKey);
        await _sessionStorage.DeleteAsync(UserKey);
    }
}

public class UserInfo
{
    public Guid Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public List<string> Roles { get; set; } = [];
    public string FullName => $"{FirstName} {LastName}";
}