using Microsoft.AspNetCore.Components;
using MediatR;
using MudBlazor;
using AutoMapper;

namespace ProxyManagement.BlazorServer.Components.Base;

public abstract class DydoxyComponentBase : ComponentBase, IDisposable
{
    [Inject] protected IMediator Mediator { get; set; } = default!;
    [Inject] protected IMapper Mapper { get; set; } = default!;
    [Inject] protected ILogger Logger { get; set; } = default!;
    [Inject] protected ISnackbar Snackbar { get; set; } = default!;
    [Inject] protected IDialogService DialogService { get; set; } = default!;
    [Inject] protected NavigationManager Navigation { get; set; } = default!;

    protected bool IsLoading { get; set; }
    protected string? ErrorMessage { get; set; }

    protected virtual async Task HandleErrorAsync(Exception exception)
    {
        Logger.LogError(exception, "Error in component {ComponentType}", GetType().Name);
        
        ErrorMessage = exception switch
        {
            UnauthorizedAccessException => "You don't have permission to perform this action",
            HttpRequestException => "Unable to connect to the server. Please try again later",
            _ => "An unexpected error occurred. Please try again"
        };

        await ShowErrorMessageAsync(ErrorMessage);
        StateHasChanged();
    }

    protected virtual Task ShowSuccessMessageAsync(string message)
    {
        Snackbar.Add(message, Severity.Success);
        return Task.CompletedTask;
    }

    protected virtual Task ShowErrorMessageAsync(string message)
    {
        Snackbar.Add(message, Severity.Error);
        return Task.CompletedTask;
    }

    protected virtual Task ShowWarningMessageAsync(string message)
    {
        Snackbar.Add(message, Severity.Warning);
        return Task.CompletedTask;
    }

    protected virtual Task ShowInfoMessageAsync(string message)
    {
        Snackbar.Add(message, Severity.Info);
        return Task.CompletedTask;
    }

    protected async Task<bool> ShowConfirmationDialogAsync(string title, string message)
    {
        var parameters = new DialogParameters
        {
            ["ContentText"] = message,
            ["ButtonText"] = "Confirm",
            ["Color"] = Color.Error
        };

        var options = new DialogOptions { CloseButton = true, MaxWidth = MaxWidth.ExtraSmall };
        var dialog = await DialogService.ShowAsync<MudDialog>(title, parameters, options);
        var result = await dialog.Result;

        return !result.Canceled;
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            // Dispose managed resources
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
}