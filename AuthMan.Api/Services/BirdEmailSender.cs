using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Encodings.Web;
using Microsoft.Extensions.Options;

namespace AuthMan.Api.Services;

public sealed class BirdEmailSender(
    HttpClient httpClient,
    IOptions<BirdEmailOptions> options) : IEmailSender
{
    private readonly BirdEmailOptions _options = options.Value;

    public async Task SendConfirmationAsync(
        string email,
        string confirmationLink,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(_options.ApiKey))
        {
            throw new InvalidOperationException("Bird API key is missing. Configure Bird:ApiKey in User Secrets or environment variables.");
        }

        if (string.IsNullOrWhiteSpace(_options.FromEmail))
        {
            throw new InvalidOperationException("Bird sender email is missing. Configure Bird:FromEmail in User Secrets or environment variables.");
        }

        var payload = new
        {
            from = new
            {
                email = _options.FromEmail,
                name = _options.FromName
            },
            to = new[]
            {
                new { email }
            },
            subject = "Confirm your AuthMan email address",
            html = $"<p>Hello,</p><p><a href=\"{HtmlEncoder.Default.Encode(confirmationLink)}\">Confirm your email address</a></p>"
        };

        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            $"{_options.BaseUrl.TrimEnd('/')}/v1/email/messages");

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _options.ApiKey);
        request.Content = JsonContent.Create(payload);

        using var response = await httpClient.SendAsync(request, cancellationToken);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(
                $"Bird email send failed with status {(int)response.StatusCode} ({response.StatusCode}). Response: {responseBody}");
        }
    }
}
