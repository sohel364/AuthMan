using AuthMan.Api.Services;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AuthMan.Api.Tests;

public sealed class AuthApiFactory : WebApplicationFactory<Program>
{
    private readonly string _connectionString =
        $"Data Source=authman-tests-{Guid.NewGuid():N};Mode=Memory;Cache=Shared";
    private readonly SqliteConnection _keepAliveConnection;

    public RecordingEmailSender EmailSender { get; } = new();

    public AuthApiFactory()
    {
        _keepAliveConnection = new SqliteConnection(_connectionString);
        _keepAliveConnection.Open();
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.ConfigureAppConfiguration((_, configuration) =>
        {
            configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:AuthDb"] = _connectionString
            });
        });

        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IEmailSender>();
            services.AddSingleton<IEmailSender>(EmailSender);
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);

        if (disposing)
        {
            _keepAliveConnection.Dispose();
        }
    }
}

public sealed class RecordingEmailSender : IEmailSender
{
    public string? LastSentEmail { get; private set; }
    public string? LastToken { get; private set; }
    public int SendCount { get; private set; }

    public Task SendConfirmationAsync(
        string email,
        string token,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        LastSentEmail = email;
        LastToken = token;
        SendCount++;
        return Task.CompletedTask;
    }
}
