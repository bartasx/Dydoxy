using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.Authorization;

namespace ProxyManagement.BlazorServer.Hubs;

[Authorize]
public class NotificationHub : Hub
{
    private readonly ILogger<NotificationHub> _logger;

    public NotificationHub(ILogger<NotificationHub> logger)
    {
        _logger = logger;
    }

    public async Task JoinUserGroup(string userId)
    {
        var groupName = $"User_{userId}";
        await Groups.AddToGroupAsync(Context.ConnectionId, groupName);
        
        _logger.LogInformation(
            "User {UserId} joined notification group {GroupName}",
            Context.UserIdentifier,
            groupName);
    }

    public async Task LeaveUserGroup(string userId)
    {
        var groupName = $"User_{userId}";
        await Groups.RemoveFromGroupAsync(Context.ConnectionId, groupName);
        
        _logger.LogInformation(
            "User {UserId} left notification group {GroupName}",
            Context.UserIdentifier,
            groupName);
    }

    public async Task MarkNotificationAsRead(string notificationId)
    {
        _logger.LogInformation(
            "User {UserId} marked notification {NotificationId} as read",
            Context.UserIdentifier,
            notificationId);
        
        // Here you would typically update the notification status in the database
        // and notify other clients if needed
    }

    public override async Task OnConnectedAsync()
    {
        _logger.LogInformation(
            "User {UserId} connected to notification hub with connection {ConnectionId}",
            Context.UserIdentifier,
            Context.ConnectionId);
        
        await base.OnConnectedAsync();
    }

    public override async Task OnDisconnectedAsync(Exception? exception)
    {
        if (exception != null)
        {
            _logger.LogError(exception,
                "User {UserId} disconnected from notification hub with error",
                Context.UserIdentifier);
        }
        else
        {
            _logger.LogInformation(
                "User {UserId} disconnected from notification hub",
                Context.UserIdentifier);
        }
        
        await base.OnDisconnectedAsync(exception);
    }
}