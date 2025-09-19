using ProxyManagement.Shared.Kernel.Primitives;
using ProxyManagement.Shared.Kernel.Results;
using System.Text.RegularExpressions;

namespace ProxyManagement.Shared.Kernel.ValueObjects;

public sealed class Email : ValueObject
{
    private static readonly Regex EmailRegex = new(
        @"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private Email(string value)
    {
        Value = value;
    }

    public string Value { get; }

    public static Result<Email> Create(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return Error.Validation("Email.Empty", "Email cannot be empty");
        }

        if (email.Length > 255)
        {
            return Error.Validation("Email.TooLong", "Email cannot be longer than 255 characters");
        }

        if (!EmailRegex.IsMatch(email))
        {
            return Error.Validation("Email.InvalidFormat", "Email format is invalid");
        }

        return new Email(email.ToLowerInvariant());
    }

    protected override IEnumerable<object?> GetEqualityComponents()
    {
        yield return Value;
    }

    public override string ToString() => Value;

    public static implicit operator string(Email email) => email.Value;
}