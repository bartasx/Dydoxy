# Project Structure & Organization

## Repository Layout

The Dydoxy repository follows a multi-language, microservices architecture with clear separation between Go backend services and C# frontend applications.

## Root Directory Structure

```
/
├── proxy-engine-go/          # Go microservices backend
├── ProxyManagement/          # C# Blazor Server frontend
├── Dydoxy/                   # Simple Blazor app (legacy/demo)
├── database/                 # Database schema and seed files
├── docs/                     # Project documentation
├── docker-compose.yml        # Development environment
└── .kiro/                    # Kiro AI assistant configuration
```

## Go Backend Services (proxy-engine-go/)

### Command Structure (cmd/)
Each microservice has its own main entry point:
- `cmd/proxy-core/` - Main proxy server (SOCKS5, HTTP)
- `cmd/modem-manager/` - 4G/5G modem control service
- `cmd/traffic-analyzer/` - Real-time traffic analysis
- `cmd/threat-detector/` - AI threat detection service
- `cmd/load-balancer/` - Traffic distribution service

### Internal Packages (internal/)
Business logic organized by domain:
- `internal/proxy/` - Proxy implementations (socks5/, http/, shadowsocks/, chain/)
- `internal/modem/` - Modem drivers (huawei/, quectel/, pool/)
- `internal/security/` - Security features (ratelimit/, filter/, threat/, geoblock/)
- `internal/analytics/` - Metrics and analytics (metrics/, events/, storage/)
- `internal/common/` - Shared utilities (config/, logging/, middleware/, models/)

### API Definitions (api/)
- `api/grpc/` - Protocol buffer definitions for service communication
- `api/rest/` - REST API handlers and documentation
- `api/websocket/` - WebSocket handlers for real-time communication

### Public Packages (pkg/)
Reusable libraries that could be extracted:
- `pkg/ai/` - AI/ML models and algorithms
- `pkg/crypto/` - Encryption and security utilities
- `pkg/protocols/` - Network protocol implementations

## C# Frontend Application (ProxyManagement/)

### Modular Monolith Structure (src/)
Organized by business capabilities following Clean Architecture:

#### Core Business Modules (src/Modules/)
Each module follows Clean Architecture with strict layer separation:

**Users Module** (`src/Modules/Users/`)
```
Users/
├── Domain/
│   ├── Entities/           # User, Role, Permission
│   ├── ValueObjects/       # Email, UserId
│   ├── Events/            # UserCreated, UserUpdated
│   └── Interfaces/        # IUserRepository
├── Application/
│   ├── Commands/          # CreateUser, UpdateUser
│   ├── Queries/           # GetUser, GetUsers
│   ├── Handlers/          # Command/Query handlers
│   ├── Validators/        # FluentValidation rules
│   └── DTOs/             # Data transfer objects
├── Infrastructure/
│   ├── Data/             # UsersDbContext, Repositories
│   ├── External/         # External service clients
│   └── Configuration/    # Module registration
└── Presentation/
    ├── Controllers/      # API endpoints
    └── Components/       # Blazor components
```

**Proxy Module** (`src/Modules/Proxy/`)
- Proxy server configuration and management
- Connection pooling and load balancing
- Protocol-specific implementations

**Security Module** (`src/Modules/Security/`)
- Security policies and threat management
- Audit logging and compliance
- Real-time threat detection

**Analytics Module** (`src/Modules/Analytics/`)
- Usage analytics and reporting
- Time-series data processing
- Custom dashboard creation

**Billing Module** (`src/Modules/Billing/`)
- Subscription and billing management
- Usage tracking and invoicing
- Payment processing integration

### Module Communication Patterns
- **Domain Events**: Cross-module communication via MediatR notifications
- **Shared Contracts**: Common interfaces in Shared/Contracts
- **API Integration**: Refit clients for external service communication
- **Database Isolation**: Separate schema per module

#### Shared Components (src/Shared/)
- `Kernel/` - Domain primitives, base classes, common abstractions
- `Infrastructure/` - Cross-cutting concerns (logging, caching, messaging)
- `Contracts/` - Inter-module communication contracts

#### Blazor Server Application (src/ProxyManagement.BlazorServer/)
- `Components/` - Blazor components organized by feature
  - `Layout/` - Application layout components
  - `Dashboard/` - Real-time dashboard components
  - `UserManagement/` - User administration UI
  - `Security/` - Security monitoring interface
  - `Analytics/` - Analytics and reporting UI
- `Pages/` - Routable Blazor pages
- `Services/` - Client-side services and state management
- `Hubs/` - SignalR hubs for real-time communication

## File Naming Conventions

### Go Files
- **Package names**: lowercase, single word (e.g., `proxy`, `modem`, `security`)
- **File names**: lowercase with underscores (e.g., `rate_limiter.go`, `modem_pool.go`)
- **Interface names**: Start with 'I' or descriptive name (e.g., `ProxyServer`, `ModemManager`)
- **Struct names**: PascalCase (e.g., `ProxyConfig`, `ModemStatus`)

### C# Files
- **Namespaces**: Follow folder structure (e.g., `ProxyManagement.Modules.Users.Domain`)
- **Classes**: PascalCase (e.g., `UserService`, `ProxyConfiguration`)
- **Interfaces**: Start with 'I' (e.g., `IUserRepository`, `IProxyService`)
- **Blazor components**: PascalCase with .razor extension (e.g., `UserList.razor`)

## Configuration Management

### Go Services
- **Environment variables**: For runtime configuration
- **YAML/JSON files**: For complex configuration structures
- **Viper**: Configuration management library
- **Config location**: `internal/common/config/`

### C# Application
- **appsettings.json**: Base configuration
- **appsettings.{Environment}.json**: Environment-specific overrides
- **User secrets**: For development credentials
- **Environment variables**: For production deployment

## Database Organization

### Schema Structure
- **Public schema**: Shared tables (organizations, users)
- **Module schemas**: Separate schema per business module
- **Audit schema**: Audit trails and compliance data
- **Analytics schema**: Time-series and reporting data

### Migration Strategy
- **Entity Framework migrations**: For C# application schema
- **SQL scripts**: For Go service-specific tables
- **Versioned migrations**: Sequential numbering with descriptive names

## Testing Structure

### Go Tests
- **Unit tests**: `*_test.go` files alongside source code
- **Integration tests**: `tests/integration/` directory
- **Test data**: `testdata/` directories for fixtures

### C# Tests
- **Unit tests**: `tests/Unit/` organized by module
- **Integration tests**: `tests/Integration/` for API testing
- **Component tests**: `tests/Component/` for Blazor components (bUnit)
- **Architecture tests**: `tests/Architecture/` for architectural rules

## Documentation Structure (docs/)

- `project_brief_prompt.md` - Complete project overview
- `tech_stack_details.md` - Detailed technology specifications
- `project_structure.md` - Architecture and organization
- `development_tasks.md` - Development roadmap and tasks
- `blazor_components.txt` - UI component specifications

## Development Workflow

### Branch Strategy
- **main**: Production-ready code
- **develop**: Integration branch for features
- **feature/***: Individual feature development
- **hotfix/***: Critical production fixes

### Code Organization Principles
- **Single Responsibility**: Each module/service has one clear purpose
- **Dependency Inversion**: Depend on abstractions, not concretions
- **Domain-Driven Design**: Organize by business capabilities, not technical layers
- **Microservices**: Services can be deployed independently
- **Clean Architecture**: Clear separation of concerns with dependency rules

### Deployment Structure
- **Docker containers**: Each service containerized
- **Docker Compose**: Local development orchestration
- **Kubernetes manifests**: Production deployment (deployments/kubernetes/)
- **Terraform**: Infrastructure as Code (deployments/terraform/)

## Key Architectural Decisions

### Communication Patterns
- **gRPC**: Service-to-service communication
- **REST APIs**: External client communication
- **SignalR**: Real-time web updates
- **Message queues**: Asynchronous processing (planned)

### Data Flow (.NET 9 CQRS Pattern)
- **Commands**: Write operations through MediatR handlers with validation pipeline
- **Queries**: Read operations with optimized projections and compiled queries
- **Domain Events**: Cross-module communication via MediatR domain event notifications
- **Integration Events**: External system communication via message queues
- **Real-time Updates**: SignalR hubs for live dashboard updates
- **Result Pattern**: Functional error handling throughout the application stack

### CQRS Implementation Details
```csharp
// Command with validation
public record CreateProxyCommand(string Name, ProxyType Type, string Endpoint) : IRequest<Result<Guid>>;

// Query with projection
public record GetProxyQuery(Guid Id) : IRequest<Result<ProxyDetailDto>>;

// Domain event
public record ProxyCreatedEvent(Guid ProxyId, string Name) : INotification;

// Result pattern
public record Result<T>(bool IsSuccess, T? Value, Error? Error)
{
    public static Result<T> Success(T value) => new(true, value, null);
    public static Result<T> Failure(Error error) => new(false, default, error);
}
```

### Security Boundaries
- **Module isolation**: Each module manages its own data
- **API gateways**: Centralized authentication and routing
- **Service mesh**: Secure service-to-service communication (planned)
- **Database access**: Repository pattern with proper authorization