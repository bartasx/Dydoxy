using MediatR;
using ProxyManagement.Shared.Kernel.Primitives;

namespace ProxyManagement.Shared.Kernel.Abstractions;

public interface IDomainEventHandler<in TDomainEvent> : INotificationHandler<TDomainEvent>
    where TDomainEvent : DomainEvent
{
}