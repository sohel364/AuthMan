using System.Net;
using System.Net.Http.Json;
using AuthMan.Api.Data;
using Microsoft.AspNetCore.WebUtilities;
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
    public async Task Register_CreatesUnconfirmedUser_AndSendsConfirmationLink()
    {
        using var response = await RegisterAsync(Email);

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.Equal(Email, _factory.EmailSender.LastSentEmail);
        Assert.StartsWith(
            "https://authman.example.test/api/auth/verify-email-link?",
            _factory.EmailSender.LastConfirmationLink);

        using var scope = _factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
        var user = await userManager.FindByEmailAsync(Email);

        Assert.NotNull(user);
        Assert.False(user.EmailConfirmed);
    }

    [Fact]
    public async Task VerifyEmailLink_WithValidToken_ConfirmsUserEmail()
    {
        using var registrationResponse = await RegisterAsync(Email);
        Assert.Equal(HttpStatusCode.Accepted, registrationResponse.StatusCode);

        var confirmationUri = new Uri(_factory.EmailSender.LastConfirmationLink!);
        var query = QueryHelpers.ParseQuery(confirmationUri.Query);
        var email = query["email"].ToString();
        var token = query["token"].ToString();

        using var landingResponse = await _client.GetAsync(confirmationUri.PathAndQuery);
        Assert.Equal(HttpStatusCode.OK, landingResponse.StatusCode);
        Assert.Contains("Confirm email", await landingResponse.Content.ReadAsStringAsync());

        using var response = await _client.PostAsync(
            "/api/auth/verify-email-link",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["email"] = email,
                ["token"] = token
            }));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Email confirmed", await response.Content.ReadAsStringAsync());

        using var scope = _factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
        var user = await userManager.FindByEmailAsync(Email);

        Assert.NotNull(user);
        Assert.True(user.EmailConfirmed);
    }

    [Fact]
    public async Task Register_DuplicateUnconfirmedEmail_ResendsConfirmationLink()
    {
        using var firstResponse = await RegisterAsync(Email);
        using var secondResponse = await RegisterAsync(Email);

        Assert.Equal(HttpStatusCode.Accepted, firstResponse.StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, secondResponse.StatusCode);
        Assert.Equal(2, _factory.EmailSender.SendCount);
    }

    [Fact]
    public async Task Register_LimitsConfirmationEmailsPerClient()
    {
        for (var attempt = 0; attempt < 5; attempt++)
        {
            using var response = await RegisterAsync(Email);
            Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        }

        using var limitedResponse = await RegisterAsync(Email);

        Assert.Equal(HttpStatusCode.TooManyRequests, limitedResponse.StatusCode);
        Assert.Equal(5, _factory.EmailSender.SendCount);
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
