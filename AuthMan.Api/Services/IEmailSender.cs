namespace AuthMan.Api.Services;

public interface IEmailSender
{
    Task SendConfirmationAsync(
        string email,
        string token,
        CancellationToken cancellationToken);
}
