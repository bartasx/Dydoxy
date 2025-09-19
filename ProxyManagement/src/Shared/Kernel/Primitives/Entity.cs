namespace ProxyManagement.Shared.Kernel.Primitives;

public abstract class Entity<TId> : IEquatable<Entity<TId>>
    where TId : class
{
    public TId Id { get; protected init; }

    protected Entity(TId id) => Id = id;

    public bool Equals(Entity<TId>? other) => 
        other is not null && Id.Equals(other.Id);

    public override bool Equals(object? obj) => 
        obj is Entity<TId> entity && Equals(entity);

    public override int GetHashCode() => Id.GetHashCode();
}