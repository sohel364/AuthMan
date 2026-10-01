using System.Net;
using System.Net.Http.Json;
using AuthMan.Api.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace AuthMan.Api.Tests;

public sealed class AuthRegistrationTests : IDisposable
{
    private const string Email = "new.user@example.com";
    private const string Password = "StrongPass123!";

    private readonly AuthApiFactory _factory;
    private readonly HttpClient _client;

    public AuthRegistrationTests()
    {
        _factory = new AuthApiFactory();
        _client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost")
        });

        using var scope = _factory.Services.CreateScope();
        var database = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        database.Database.EnsureCreated();
    }

    [Fact]
    public async Task Register_CreatesUnconfirmedUser_AndSendsConfirmationToken()
    {
        using var response = await RegisterAsync(Email);

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.Equal(Email, _factory.EmailSender.LastSentEmail);
        Assert.False(string.IsNullOrWhiteSpace(_factory.EmailSender.LastToken));

        using var scope = _factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
        var user = await userManager.FindByEmailAsync(Email);

        Assert.NotNull(user);
        Assert.False(user.EmailConfirmed);
    }

    [Fact]
    public async Task VerifyEmail_WithValidToken_ConfirmsUserEmail()
    {
        using var registrationResponse = await RegisterAsync(Email);
        Assert.Equal(HttpStatusCode.Accepted, registrationResponse.StatusCode);

        using var response = await _client.PostAsJsonAsync(
            "/api/auth/verify-email",
            new
            {
                email = Email,
                token = _factory.EmailSender.LastToken
            });

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

        using var scope = _factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
        var user = await userManager.FindByEmailAsync(Email);

        Assert.NotNull(user);
        Assert.True(user.EmailConfirmed);
    }

    [Fact]
    public async Task Register_DuplicateEmail_DoesNotSendAnotherToken()
    {
        using var firstResponse = await RegisterAsync(Email);
        using var secondResponse = await RegisterAsync(Email);

        Assert.Equal(HttpStatusCode.Accepted, firstResponse.StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, secondResponse.StatusCode);
        Assert.Equal(1, _factory.EmailSender.SendCount);
    }

    [Fact]
    public async Task VerifyEmail_WithInvalidToken_ReturnsBadRequest()
    {
        using var response = await _client.PostAsJsonAsync(
            "/api/auth/verify-email",
            new
            {
                email = Email,
                token = "not-a-valid-token"
            });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Register_WithInvalidEmail_ReturnsBadRequest()
    {
        using var response = await _client.PostAsJsonAsync(
            "/api/auth/register",
            new
            {
                email = "not-an-email",
                password = Password
            });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(0, _factory.EmailSender.SendCount);
    }

    private Task<HttpResponseMessage> RegisterAsync(string email) =>
        _client.PostAsJsonAsync(
            "/api/auth/register",
            new
            {
                email,
                password = Password
            });

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }
}
