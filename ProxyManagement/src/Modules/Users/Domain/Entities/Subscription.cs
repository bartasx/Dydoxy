using ProxyManagement.Shared.Kernel.Primitives;

namespace ProxyManagement.Modules.Users.Domain.Entities;

public class Subscription : Entity<SubscriptionId>
{
    public OrganizationId OrganizationId { get; private set; }
    public PlanType Plan { get; private set; }
    public Dictionary<string, object> Limits { get; private set; }
    public DateTimeOffset? ExpiresAt { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset UpdatedAt { get; private set; }

    private Subscription(SubscriptionId id, OrganizationId organizationId, PlanType plan, DateTimeOffset? expiresAt) : base(id)
    {
        OrganizationId = organizationId;
        Plan = plan;
        Limits = new Dictionary<string, object>();
        ExpiresAt = expiresAt;
        CreatedAt = DateTimeOffset.UtcNow;
        UpdatedAt = DateTimeOffset.UtcNow;
    }

    public static Subscription Create(OrganizationId organizationId, PlanType plan, DateTimeOffset? expiresAt = null)
    {
        var id = new SubscriptionId(Guid.NewGuid());
        return new Subscription(id, organizationId, plan, expiresAt);
    }

    public void UpdatePlan(PlanType plan, DateTimeOffset? expiresAt = null)
    {
        Plan = plan;
        ExpiresAt = expiresAt;
        UpdatedAt = DateTimeOffset.UtcNow;
    }

    public bool IsActive => ExpiresAt == null || ExpiresAt > DateTimeOffset.UtcNow;
}

public record SubscriptionId(Guid Value);