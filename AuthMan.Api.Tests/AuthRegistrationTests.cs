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

    [Fact]
    public async Task OpenIddictDiscovery_ReturnsAuthorizationCodeAndPkceEndpoints()
    {
        using var response = await _client.GetAsync("/.well-known/openid-configuration");
        var discovery = await response.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("https://localhost/connect/authorize", discovery.GetProperty("authorization_endpoint").GetString());
        Assert.Equal("https://localhost/connect/token", discovery.GetProperty("token_endpoint").GetString());
        Assert.Contains(
            "code",
            discovery.GetProperty("response_types_supported").EnumerateArray().Select(value => value.GetString()));
        Assert.Contains(
            "S256",
            discovery.GetProperty("code_challenge_methods_supported").EnumerateArray().Select(value => value.GetString()));
    }

    [Fact]
    public async Task IdentityLoginPage_IsAvailable()
    {
        using var response = await _client.GetAsync("/Identity/Account/Login");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Log in", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task AuthorizationRequest_ForRegisteredClient_RedirectsAnonymousUserToLogin()
    {
        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });

        using var response = await client.GetAsync(
            "/connect/authorize?client_id=authman-web-dev&redirect_uri=https%3A%2F%2Flocalhost%3A5173%2Fsignin-oidc&response_type=code&scope=openid%20email&code_challenge=abc123&code_challenge_method=S256&state=test-state");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.StartsWith("https://localhost/Identity/Account/Login?ReturnUrl=", response.Headers.Location?.OriginalString);
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
