namespace ProxyManagement.Shared.Kernel.Primitives;

public abstract class ValueObject : IEquatable<ValueObject>
{
    public static bool operator ==(ValueObject? first, ValueObject? second)
    {
        return first is not null && second is not null && first.Equals(second);
    }

    public static bool operator !=(ValueObject? first, ValueObject? second)
    {
        return !(first == second);
    }

    public bool Equals(ValueObject? other)
    {
        if (other is null || other.GetType() != GetType())
        {
            return false;
        }

        return GetEqualityComponents().SequenceEqual(other.GetEqualityComponents());
    }

    public override bool Equals(object? obj)
    {
        if (obj is null)
        {
            return false;
        }

        if (obj.GetType() != GetType())
        {
            return false;
        }

        if (obj is not ValueObject valueObject)
        {
            return false;
        }

        return GetEqualityComponents().SequenceEqual(valueObject.GetEqualityComponents());
    }

    public override int GetHashCode()
    {
        return GetEqualityComponents()
            .Aggregate(default(int), (hashcode, value) =>
                HashCode.Combine(hashcode, value?.GetHashCode() ?? 0));
    }

    protected abstract IEnumerable<object?> GetEqualityComponents();
}