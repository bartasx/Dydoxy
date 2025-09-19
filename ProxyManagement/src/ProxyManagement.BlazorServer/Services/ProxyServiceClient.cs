using Grpc.Net.Client;

namespace ProxyManagement.BlazorServer.Services;

public class ProxyServiceClient
{
    private readonly GrpcChannel _channel;
    private readonly ILogger<ProxyServiceClient> _logger;

    public ProxyServiceClient(IConfiguration configuration, ILogger<ProxyServiceClient> logger)
    {
        var address = configuration.GetConnectionString("ProxyService") ?? "https://localhost:9090";
        _channel = GrpcChannel.ForAddress(address);
        _logger = logger;
    }

    public async Task<ServerStats> GetServerStatsAsync(string serverId)
    {
        try
        {
            // This would use the generated gRPC client
            // For now, return mock data
            return new ServerStats
            {
                ServerId = serverId,
                Status = "online",
                ActiveConnections = 150,
                BytesTransferred = 1024 * 1024 * 500 // 500MB
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get server stats for {ServerId}", serverId);
            throw;
        }
    }

    public async Task<UserStats> GetUserStatsAsync(string userId)
    {
        try
        {
            return new UserStats
            {
                UserId = userId,
                BytesUp = 1024 * 1024 * 100, // 100MB
                BytesDown = 1024 * 1024 * 400, // 400MB
                Requests = 1250
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get user stats for {UserId}", userId);
            throw;
        }
    }

    public void Dispose()
    {
        _channel?.Dispose();
    }
}

public record ServerStats(string ServerId, string Status, int ActiveConnections, long BytesTransferred);
public record UserStats(string UserId, long BytesUp, long BytesDown, int Requests);