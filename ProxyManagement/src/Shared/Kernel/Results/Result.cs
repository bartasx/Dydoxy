namespace ProxyManagement.Shared.Kernel.Results;

public record Result(bool IsSuccess, Error? Error = null)
{
    public static Result Success() => new(true);
    public static Result Failure(Error error) => new(false, error);
    
    public static implicit operator Result(Error error) => Failure(error);
}

public record Result<T>(bool IsSuccess, T? Value = default, Error? Error = null)
{
    public static Result<T> Success(T value) => new(true, value);
    public static Result<T> Failure(Error error) => new(false, default, error);
    
    public static implicit operator Result<T>(T value) => Success(value);
    public static implicit operator Result<T>(Error error) => Failure(error);
}

public record Error(string Code, string Message);

public static class Errors
{
    public static class General
    {
        public static Error NotFound(string entity, object id) => 
            new($"{entity}.NotFound", $"{entity} with id {id} was not found");
        
        public static Error Validation(string message) => 
            new("General.Validation", message);
    }
}