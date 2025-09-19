using Microsoft.Extensions.DependencyInjection;
using FluentValidation;
using MediatR;
using System.Reflection;

namespace ProxyManagement.Shared.Kernel.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddSharedKernel(this IServiceCollection services)
    {
        services.AddMediatR(cfg => cfg.RegisterServicesFromAssembly(Assembly.GetExecutingAssembly()));
        services.AddValidatorsFromAssembly(Assembly.GetExecutingAssembly());
        
        return services;
    }

    public static IServiceCollection AddModule<TModule>(this IServiceCollection services)
        where TModule : class, IModule
    {
        var module = Activator.CreateInstance<TModule>();
        module.RegisterServices(services);
        
        return services;
    }
}

public interface IModule
{
    void RegisterServices(IServiceCollection services);
}