using MudBlazor.Services;
using MediatR;
using FluentValidation;
using Microsoft.AspNetCore.Components.Authorization;
using ProxyManagement.BlazorServer.Hubs;
using ProxyManagement.BlazorServer.Infrastructure.Behaviors;
using ProxyManagement.BlazorServer.Services.Authentication;
using ProxyManagement.Shared.Kernel.Extensions;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

// Add Serilog
builder.Host.UseSerilog((context, configuration) =>
    configuration.ReadFrom.Configuration(context.Configuration));

// Add services
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddMudServices();
builder.Services.AddSignalR();

// Add MediatR with behaviors
builder.Services.AddMediatR(cfg =>
{
    cfg.RegisterServicesFromAssembly(typeof(Program).Assembly);
    cfg.AddBehavior(typeof(IPipelineBehavior<,>), typeof(LoggingBehavior<,>));
    cfg.AddBehavior(typeof(IPipelineBehavior<,>), typeof(ValidationBehavior<,>));
});

// Add FluentValidation
builder.Services.AddValidatorsFromAssembly(typeof(Program).Assembly);

// Add Shared Kernel
builder.Services.AddSharedKernel();

// Add AutoMapper
builder.Services.AddAutoMapper(typeof(Program).Assembly);

// Add authentication and authorization services
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<IAuthenticationService, AuthenticationService>();
builder.Services.AddScoped<AuthenticationStateProvider, CustomAuthenticationStateProvider>();

builder.Services.AddAuthentication()
    .AddCookie(options =>
    {
        options.LoginPath = "/login";
        options.LogoutPath = "/logout";
        options.AccessDeniedPath = "/access-denied";
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
    options.AddPolicy("UserManagement", policy => policy.RequireRole("Admin", "UserManager"));
    options.AddPolicy("ProxyManagement", policy => policy.RequireRole("Admin", "ProxyManager"));
    options.AddPolicy("SecurityManagement", policy => policy.RequireRole("Admin", "SecurityManager"));
});

var app = builder.Build();

// Configure pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.UseAntiforgery();

app.MapRazorComponents<ProxyManagement.BlazorServer.Components.App>()
    .AddInteractiveServerRenderMode();

app.MapHub<DashboardHub>("/hubs/dashboard");
app.MapHub<NotificationHub>("/hubs/notifications");

app.Run();