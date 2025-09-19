# Technology Stack & Build System

## Architecture Overview

Dydoxy uses a microservices architecture with Go backend services and a C# Blazor Server frontend, designed for enterprise-scale proxy management.

## Backend Technology Stack (Go)

### Core Framework & Libraries
- **Web Framework**: Gin (github.com/gin-gonic/gin) for HTTP APIs
- **gRPC**: google.golang.org/grpc for service communication
- **Database**: PostgreSQL with lib/pq driver
- **Caching**: Redis with go-redis/redis/v9
- **WebSockets**: gorilla/websocket for real-time communication

### Proxy & Networking
- **SOCKS5**: armon/go-socks5 for SOCKS5 proxy implementation
- **HTTP Proxy**: Custom implementation in internal/proxy/http/
- **Shadowsocks**: Integration planned for advanced protocols
- **Rate Limiting**: ulule/limiter/v3 for traffic control

### Security & Monitoring
- **Logging**: sirupsen/logrus for structured logging
- **Metrics**: prometheus/client_golang for monitoring
- **GeoIP**: oschwald/geoip2-golang for geographic blocking
- **Modem Integration**: knq/hilink for Huawei modem control

### Configuration & Utilities
- **Config**: spf13/viper for configuration management
- **CLI**: spf13/cobra for command-line tools
- **UUID**: google/uuid for unique identifiers

## Frontend Technology Stack (C# .NET 9)

### Core Framework
- **.NET 9**: Latest version with enhanced performance and features
- **Blazor Server**: Server-side rendering with SignalR for real-time updates
- **Entity Framework Core**: PostgreSQL integration with EFCore.NamingConventions
- **Minimal APIs**: For lightweight API endpoints where appropriate

### UI Components & Libraries
- **MudBlazor**: Primary UI component library for rich interfaces
- **SignalR**: Real-time communication between server and clients
- **MediatR**: CQRS pattern implementation for clean architecture
- **Refit**: Type-safe HTTP client for external API communication
- **FluentValidation**: Input validation for commands and DTOs

### Architecture Patterns
- **Clean Architecture**: Domain, Application, Infrastructure, Presentation layers with strict dependency rules
- **CQRS**: Command Query Responsibility Segregation with MediatR handlers
- **Modular Monolith**: Self-contained modules with clear boundaries (Users, Proxy, Security, Analytics, Billing)
- **Domain-Driven Design**: Aggregates, Value Objects, Domain Services, Repository Pattern
- **Vertical Slice Architecture**: Feature-based organization within modules
- **Result Pattern**: Functional error handling without exceptions

## Database & Infrastructure

### Primary Database
- **PostgreSQL 16**: Main data store for all application data
- **Redis 7**: Caching and real-time data storage
- **Entity Framework Migrations**: Database schema versioning

### Containerization
- **Docker**: All services containerized for consistent deployment
- **Docker Compose**: Local development environment orchestration
- **Multi-stage builds**: Optimized container images

## Common Build & Development Commands

### Go Backend Services
```bash
# Build all services
cd proxy-engine-go
go mod tidy
go build -o bin/ ./cmd/...

# Run specific service
go run ./cmd/proxy-core/main.go
go run ./cmd/modem-manager/main.go

# Run tests
go test ./...
go test -race ./...

# Generate protobuf files
protoc --go_out=. --go-grpc_out=. api/grpc/*.proto
```

### C# Blazor Application
```bash
# Restore packages
cd ProxyManagement/src/ProxyManagement.BlazorServer
dotnet restore

# Build application
dotnet build
dotnet build --configuration Release

# Run application
dotnet run
dotnet watch run  # Hot reload for development

# Run tests
dotnet test
dotnet test --collect:"XPlat Code Coverage"

# Entity Framework migrations
dotnet ef migrations add MigrationName
dotnet ef database update
```

### Docker Development Environment
```bash
# Start all services
docker-compose up -d

# Rebuild and start
docker-compose up --build

# View logs
docker-compose logs -f proxy-core
docker-compose logs -f

# Stop services
docker-compose down
```

### Database Operations
```bash
# Connect to PostgreSQL
docker-compose exec postgres psql -U dydoxy -d dydoxy

# Redis CLI
docker-compose exec redis redis-cli

# Run database migrations
cd ProxyManagement/src/ProxyManagement.BlazorServer
dotnet ef database update
```

## Development Environment Setup

### Prerequisites
- **Go 1.23+**: Backend services development
- **.NET 8 SDK**: Frontend application development
- **Docker & Docker Compose**: Container orchestration
- **PostgreSQL Client**: Database management (optional)
- **Git**: Version control

### Quick Start
```bash
# Clone repository
git clone <repository-url>
cd dydoxy

# Start infrastructure
docker-compose up -d postgres redis

# Run Go services
cd proxy-engine-go
go mod tidy
go run ./cmd/proxy-core/main.go

# Run Blazor app (separate terminal)
cd ProxyManagement/src/ProxyManagement.BlazorServer
dotnet restore
dotnet run
```

## Code Quality & Standards

### Go Standards
- **gofmt**: Standard Go formatting
- **golint**: Code style checking
- **go vet**: Static analysis
- **Structured logging**: Use logrus with consistent fields
- **Error handling**: Explicit error returns, no panics in production code

### C# Standards (.NET 9)

#### Clean Architecture Enforcement
- **Dependency Rule**: Dependencies must point inward only (Presentation → Application → Domain)
- **Layer Separation**: No direct references between Infrastructure and Presentation layers
- **Domain Purity**: Domain layer has no external dependencies
- **Interface Segregation**: Small, focused interfaces in Application layer

#### CQRS Implementation
- **Command Handlers**: One handler per command using MediatR.IRequestHandler<TCommand, TResponse>
- **Query Handlers**: Separate read models optimized for specific use cases
- **Command Validation**: FluentValidation pipeline behavior for all commands
- **Query Optimization**: Use projection and compiled queries for performance
- **Event Sourcing**: Domain events for cross-module communication

#### Modular Monolith Principles
- **Module Boundaries**: Each module is self-contained with its own database schema
- **Inter-Module Communication**: Only through published domain events or shared contracts
- **Module Registration**: Each module registers its own services via IServiceCollection extensions
- **Database Isolation**: Separate DbContext per module with schema separation

#### Performance & Query Optimization
- **EF Core Best Practices**: 
  - Use AsNoTracking() for read-only queries
  - Implement query splitting for complex joins
  - Use compiled queries for frequently executed queries
  - Leverage bulk operations for large data sets
- **Caching Strategy**: Multi-level caching (Memory → Redis → Database)
- **Async Patterns**: ConfigureAwait(false) in library code, proper cancellation token usage

#### HTTP Client Management
- **Refit Integration**: Type-safe HTTP clients for external APIs
- **HttpClientFactory**: Proper lifetime management and configuration
- **Polly Resilience**: Retry policies, circuit breakers, timeouts
- **Typed Clients**: Strongly-typed API clients with dependency injection

#### Code Quality Standards
- **EditorConfig**: Consistent formatting across team
- **Nullable Reference Types**: Enabled project-wide with strict warnings
- **Async/Await**: All I/O operations must be asynchronous
- **Result Pattern**: Use Result<T> for business logic error handling, exceptions only for infrastructure failures
- **Immutable Records**: Prefer records for DTOs and value objects
- **Primary Constructors**: Use for dependency injection in .NET 9
- **Collection Expressions**: Use new collection syntax where applicable

#### Testing Standards
- **Unit Tests**: Test domain logic and handlers in isolation
- **Integration Tests**: Use WebApplicationFactory for API testing
- **Architecture Tests**: Enforce architectural rules with NetArchTest
- **Test Containers**: Use Testcontainers for integration tests with real databases

## Performance Considerations

### Go Services
- **Connection Pooling**: Optimized database connections
- **Goroutine Management**: Proper cleanup and context cancellation
- **Memory Management**: Avoid memory leaks in long-running services
- **Caching**: Redis for frequently accessed data

### Blazor Application (.NET 9)
- **SignalR**: Real-time updates without polling using streaming and automatic reconnection
- **Component Lifecycle**: Proper disposal of resources with IAsyncDisposable
- **State Management**: Fluxor for complex state or simple services for basic state
- **Lazy Loading**: Load components and data on demand with dynamic imports
- **Streaming Rendering**: Use @rendermode for optimal performance
- **Component Virtualization**: Use Virtualize component for large data sets
- **Form Handling**: EditForm with FluentValidation integration
- **Error Boundaries**: Implement ErrorBoundary components for graceful error handling

### Additional .NET 9 Features & Libraries

#### Essential NuGet Packages
```xml
<!-- Core Framework -->
<PackageReference Include="Microsoft.AspNetCore.App" Version="9.0.0" />
<PackageReference Include="Microsoft.EntityFrameworkCore" Version="9.0.0" />
<PackageReference Include="Microsoft.EntityFrameworkCore.PostgreSQL" Version="9.0.0" />

<!-- Architecture & Patterns -->
<PackageReference Include="MediatR" Version="12.2.0" />
<PackageReference Include="FluentValidation.AspNetCore" Version="11.3.0" />
<PackageReference Include="AutoMapper.Extensions.Microsoft.DependencyInjection" Version="12.0.1" />

<!-- HTTP Clients -->
<PackageReference Include="Refit" Version="7.0.0" />
<PackageReference Include="Refit.HttpClientFactory" Version="7.0.0" />
<PackageReference Include="Microsoft.Extensions.Http.Polly" Version="9.0.0" />

<!-- UI & Real-time -->
<PackageReference Include="MudBlazor" Version="6.11.2" />
<PackageReference Include="Microsoft.AspNetCore.SignalR.Client" Version="9.0.0" />
<PackageReference Include="Fluxor.Blazor.Web" Version="5.9.1" />

<!-- Caching & Performance -->
<PackageReference Include="Microsoft.Extensions.Caching.StackExchangeRedis" Version="9.0.0" />
<PackageReference Include="Microsoft.Extensions.Caching.Memory" Version="9.0.0" />

<!-- Testing -->
<PackageReference Include="Microsoft.AspNetCore.Mvc.Testing" Version="9.0.0" />
<PackageReference Include="bunit" Version="1.24.10" />
<PackageReference Include="NetArchTest.Rules" Version="1.3.2" />
<PackageReference Include="Testcontainers.PostgreSql" Version="3.6.0" />

<!-- Observability -->
<PackageReference Include="Serilog.AspNetCore" Version="8.0.0" />
<PackageReference Include="OpenTelemetry.Extensions.Hosting" Version="1.6.0" />
<PackageReference Include="OpenTelemetry.Instrumentation.AspNetCore" Version="1.6.0" />
```

#### Module Structure Template
```csharp
// Module registration pattern
public static class ModuleExtensions
{
    public static IServiceCollection AddUsersModule(this IServiceCollection services, IConfiguration configuration)
    {
        // Register module-specific services
        services.AddScoped<IUserRepository, UserRepository>();
        services.AddMediatR(cfg => cfg.RegisterServicesFromAssembly(Assembly.GetExecutingAssembly()));
        
        // Register module DbContext
        services.AddDbContext<UsersDbContext>(options =>
            options.UseNpgsql(configuration.GetConnectionString("DefaultConnection"),
                b => b.MigrationsHistoryTable("__EFMigrationsHistory", "users")));
        
        return services;
    }
}

// CQRS Handler example
public record CreateUserCommand(string Email, string Name) : IRequest<Result<Guid>>;

public class CreateUserHandler : IRequestHandler<CreateUserCommand, Result<Guid>>
{
    private readonly IUserRepository _repository;
    private readonly IValidator<CreateUserCommand> _validator;

    public CreateUserHandler(IUserRepository repository, IValidator<CreateUserCommand> validator)
    {
        _repository = repository;
        _validator = validator;
    }

    public async Task<Result<Guid>> Handle(CreateUserCommand request, CancellationToken cancellationToken)
    {
        var validationResult = await _validator.ValidateAsync(request, cancellationToken);
        if (!validationResult.IsValid)
            return Result<Guid>.Failure(new ValidationError(validationResult.Errors));

        var user = User.Create(request.Email, request.Name);
        await _repository.AddAsync(user, cancellationToken);
        
        return Result<Guid>.Success(user.Id);
    }
}

// Refit API client example
public interface IProxyApiClient
{
    [Get("/api/proxies")]
    Task<ApiResponse<List<ProxyDto>>> GetProxiesAsync(CancellationToken cancellationToken = default);
    
    [Post("/api/proxies")]
    Task<ApiResponse<ProxyDto>> CreateProxyAsync([Body] CreateProxyRequest request, CancellationToken cancellationToken = default);
}
```