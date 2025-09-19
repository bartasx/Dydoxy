using ProxyManagement.Shared.Kernel.Primitives;

namespace ProxyManagement.Modules.Users.Domain.Entities;

public class User : Entity<UserId>
{
    public OrganizationId OrganizationId { get; private set; }
    public Email Email { get; private set; }
    public string PasswordHash { get; private set; }
    public UserRole Role { get; private set; }
    public bool IsActive { get; private set; }
    public Dictionary<string, object> Limits { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset UpdatedAt { get; private set; }

    private User(UserId id, OrganizationId organizationId, Email email, string passwordHash, UserRole role) : base(id)
    {
        OrganizationId = organizationId;
        Email = email;
        PasswordHash = passwordHash;
        Role = role;
        IsActive = true;
        Limits = new Dictionary<string, object>();
        CreatedAt = DateTimeOffset.UtcNow;
        UpdatedAt = DateTimeOffset.UtcNow;
    }

    public static User Create(OrganizationId organizationId, Email email, string passwordHash, UserRole role = UserRole.User)
    {
        var id = new UserId(Guid.NewGuid());
        return new User(id, organizationId, email, passwordHash, role);
    }

    public void Deactivate()
    {
        IsActive = false;
        UpdatedAt = DateTimeOffset.UtcNow;
    }
}

public record UserId(Guid Value);
public record Email(string Value);

public enum UserRole
{
    User,
    Admin,
    SuperAdmin
}