namespace AuthMan.Api.Services;

/// <summary>
/// Development-only email sender that writes confirmation tokens to application logs.
/// Replace this with a real email provider before production deployment.
/// </summary>
public sealed class DevelopmentEmailSender(
    ILogger<DevelopmentEmailSender> logger) : IEmailSender
{
    public Task SendConfirmationAsync(
        string email,
        string token,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        logger.LogWarning(
            "DEV ONLY: Email confirmation token for {Email}: {Token}",
            email,
            token);

        return Task.CompletedTask;
    }
}
