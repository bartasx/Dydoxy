using MediatR;

namespace ProxyManagement.Shared.Kernel.Primitives;

public interface IDomainEvent : INotification
{
    Guid Id { get; }
    DateTime OccurredOn { get; }
}