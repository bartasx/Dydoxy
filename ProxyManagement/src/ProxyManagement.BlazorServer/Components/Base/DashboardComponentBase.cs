using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.SignalR.Client;

namespace ProxyManagement.BlazorServer.Components.Base;

public abstract class DashboardComponentBase : DydoxyComponentBase
{
    [Inject] protected IConfiguration Configuration { get; set; } = default!;

    protected HubConnection? HubConnection { get; private set; }
    protected bool IsConnected => HubConnection?.State == HubConnectionState.Connected;

    protected override async Task OnInitializedAsync()
    {
        try
        {
            await ConnectToHub();
            await LoadInitialData();
        }
        catch (Exception ex)
        {
            await HandleErrorAsync(ex);
        }
    }

    protected virtual async Task ConnectToHub()
    {
        var hubUrl = GetHubUrl();
        if (string.IsNullOrEmpty(hubUrl))
        {
            Logger.LogWarning("Hub URL not configured for {ComponentType}", GetType().Name);
            return;
        }

        HubConnection = new HubConnectionBuilder()
            .WithUrl(hubUrl)
            .WithAutomaticReconnect()
            .Build();

        HubConnection.Reconnecting += OnReconnecting;
        HubConnection.Reconnected += OnReconnected;
        HubConnection.Closed += OnConnectionClosed;

        await HubConnection.StartAsync();
        await OnHubConnected();
    }

    protected abstract string GetHubUrl();
    protected abstract Task LoadInitialData();
    protected virtual Task OnHubConnected() => Task.CompletedTask;

    protected virtual Task OnReconnecting(Exception? exception)
    {
        Logger.LogInformation("Hub connection reconnecting...");
        return Task.CompletedTask;
    }

    protected virtual Task OnReconnected(string? connectionId)
    {
        Logger.LogInformation("Hub connection reconnected with ID: {ConnectionId}", connectionId);
        return OnHubConnected();
    }

    protected virtual Task OnConnectionClosed(Exception? exception)
    {
        if (exception != null)
        {
            Logger.LogError(exception, "Hub connection closed with error");
        }
        else
        {
            Logger.LogInformation("Hub connection closed");
        }
        return Task.CompletedTask;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            HubConnection?.DisposeAsync();
        }
        base.Dispose(disposing);
    }
}