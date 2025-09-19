using MudBlazor.Services;
using MediatR;
using ProxyManagement.BlazorServer.Hubs;
using ProxyManagement.BlazorServer.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();
builder.Services.AddMudServices();
builder.Services.AddSignalR();
builder.Services.AddMediatR(cfg => cfg.RegisterServicesFromAssembly(typeof(Program).Assembly));
builder.Services.AddScoped<ProxyServiceClient>();

var app = builder.Build();

// Configure pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseAntiforgery();

app.MapRazorComponents<ProxyManagement.BlazorServer.Components.App>()
    .AddInteractiveServerRenderMode();
app.MapHub<DashboardHub>("/dashboardHub");

app.Run();