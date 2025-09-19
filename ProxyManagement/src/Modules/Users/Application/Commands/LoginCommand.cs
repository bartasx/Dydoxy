using MediatR;
using ProxyManagement.Shared.Kernel.Results;

namespace ProxyManagement.Modules.Users.Application.Commands;

public record LoginCommand(string Email, string Password) : IRequest<Result<LoginResponse>>;

public record LoginResponse(string Token, string RefreshToken, UserDto User);

public record UserDto(Guid Id, string Email, string Role, string OrganizationName);

public class LoginCommandHandler : IRequestHandler<LoginCommand, Result<LoginResponse>>
{
    public async Task<Result<LoginResponse>> Handle(LoginCommand request, CancellationToken cancellationToken)
    {
        // Mock implementation - replace with real authentication
        if (request.Email == "admin@test.com" && request.Password == "password")
        {
            var user = new UserDto(
                Guid.NewGuid(),
                request.Email,
                "Admin",
                "Test Organization"
            );

            var response = new LoginResponse(
                "mock_jwt_token",
                "mock_refresh_token",
                user
            );

            return Result<LoginResponse>.Success(response);
        }

        return Result<LoginResponse>.Failure(new Error("Auth.InvalidCredentials", "Invalid email or password"));
    }
}