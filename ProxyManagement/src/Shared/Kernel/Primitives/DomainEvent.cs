using MediatR;

namespace ProxyManagement.Shared.Kernel.Primitives;

public abstract record DomainEvent(Guid Id, DateTime OccurredOnUtc) : INotification
{
    protected DomainEvent() : this(Guid.NewGuid(), DateTime.UtcNow)
    {
    }
}