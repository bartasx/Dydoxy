using ProxyManagement.Shared.Kernel.Primitives;
using ProxyManagement.Shared.Kernel.Results;

namespace ProxyManagement.Shared.Kernel.ValueObjects;

public sealed class PersonName : ValueObject
{
    private PersonName(string firstName, string lastName)
    {
        FirstName = firstName;
        LastName = lastName;
    }

    public string FirstName { get; }
    public string LastName { get; }
    public string FullName => $"{FirstName} {LastName}";

    public static Result<PersonName> Create(string firstName, string lastName)
    {
        if (string.IsNullOrWhiteSpace(firstName))
        {
            return Error.Validation("PersonName.FirstNameEmpty", "First name cannot be empty");
        }

        if (string.IsNullOrWhiteSpace(lastName))
        {
            return Error.Validation("PersonName.LastNameEmpty", "Last name cannot be empty");
        }

        if (firstName.Length > 100)
        {
            return Error.Validation("PersonName.FirstNameTooLong", "First name cannot be longer than 100 characters");
        }

        if (lastName.Length > 100)
        {
            return Error.Validation("PersonName.LastNameTooLong", "Last name cannot be longer than 100 characters");
        }

        return new PersonName(firstName.Trim(), lastName.Trim());
    }

    protected override IEnumerable<object?> GetEqualityComponents()
    {
        yield return FirstName;
        yield return LastName;
    }

    public override string ToString() => FullName;
}