using Microsoft.AspNetCore.SignalR;

namespace ProxyManagement.BlazorServer.Hubs;

public class DashboardHub : Hub
{
    public async Task JoinGroup(string groupName)
    {
        await Groups.AddToGroupAsync(Context.ConnectionId, groupName);
    }

    public async Task LeaveGroup(string groupName)
    {
        await Groups.RemoveFromGroupAsync(Context.ConnectionId, groupName);
    }

    public override async Task OnConnectedAsync()
    {
        await Clients.Caller.SendAsync("Connected", Context.ConnectionId);
        await base.OnConnectedAsync();
    }

    public override async Task OnDisconnectedAsync(Exception? exception)
    {
        await base.OnDisconnectedAsync(exception);
    }
}

public static class DashboardHubExtensions
{
    public static async Task SendStatsUpdate(this IHubContext<DashboardHub> hubContext, object stats)
    {
        await hubContext.Clients.All.SendAsync("StatsUpdate", stats);
    }

    public static async Task SendAlert(this IHubContext<DashboardHub> hubContext, object alert)
    {
        await hubContext.Clients.All.SendAsync("NewAlert", alert);
    }
}