using ProxyManagement.Shared.Kernel.Primitives;

namespace ProxyManagement.Modules.Users.Domain.Entities;

public class Organization : AggregateRoot<OrganizationId>
{
    public string Name { get; private set; }
    public PlanType PlanType { get; private set; }
    public Dictionary<string, object> Settings { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset UpdatedAt { get; private set; }

    private Organization(OrganizationId id, string name, PlanType planType) : base(id)
    {
        Name = name;
        PlanType = planType;
        Settings = new Dictionary<string, object>();
        CreatedAt = DateTimeOffset.UtcNow;
        UpdatedAt = DateTimeOffset.UtcNow;
    }

    public static Organization Create(string name, PlanType planType = PlanType.Starter)
    {
        var id = new OrganizationId(Guid.NewGuid());
        return new Organization(id, name, planType);
    }

    public void UpdatePlan(PlanType planType)
    {
        PlanType = planType;
        UpdatedAt = DateTimeOffset.UtcNow;
    }
}

public record OrganizationId(Guid Value);

public enum PlanType
{
    Starter,
    Professional,
    Enterprise,
    EnterprisePlus
}