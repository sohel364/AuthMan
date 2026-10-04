namespace AuthMan.Api.Services;

public interface IEmailSender
{
    Task SendConfirmationAsync(
        string email,
        string confirmationLink,
        CancellationToken cancellationToken);
}
