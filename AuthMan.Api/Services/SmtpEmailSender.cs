using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;
using System.Text.Encodings.Web;

namespace AuthMan.Api.Services;

public sealed class SmtpEmailSender(IOptions<EmailOptions> options) : IEmailSender
{
    private readonly EmailOptions _options = options.Value;

    public async Task SendConfirmationAsync(
        string email,
        string confirmationLink,
        CancellationToken cancellationToken)
    {
        var message = new MimeMessage();
        message.From.Add(new MailboxAddress(_options.FromName, _options.FromAddress));
        message.To.Add(MailboxAddress.Parse(email));
        message.Subject = "Confirm your AuthMan email address";

        var safeEmail = HtmlEncoder.Default.Encode(email);
        var safeLink = HtmlEncoder.Default.Encode(confirmationLink);
        message.Body = new BodyBuilder
        {
            TextBody = $"Confirm your email address by opening this link: {confirmationLink}",
            HtmlBody = $"<p>Hello {safeEmail},</p><p><a href=\"{safeLink}\">Confirm your email address</a></p>"
        }.ToMessageBody();

        using var client = new SmtpClient();
        var socketOptions = _options.UseSsl
            ? SecureSocketOptions.SslOnConnect
            : _options.UseStartTls
                ? SecureSocketOptions.StartTls
                : SecureSocketOptions.None;

        await client.ConnectAsync(
            _options.Host,
            _options.Port,
            socketOptions,
            cancellationToken);

        try
        {
            if (!string.IsNullOrWhiteSpace(_options.UserName))
            {
                await client.AuthenticateAsync(
                    _options.UserName,
                    _options.Password,
                    cancellationToken);
            }

            await client.SendAsync(message, cancellationToken);
        }
        finally
        {
            if (client.IsConnected)
            {
                await client.DisconnectAsync(true, CancellationToken.None);
            }
        }
    }
}