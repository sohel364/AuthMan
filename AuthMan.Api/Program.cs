using AuthMan.Api.Data;
using AuthMan.Api.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using System.Security.Cryptography.X509Certificates;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddRazorPages();
builder.Services.AddOpenApi();
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("registration", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            }));
});

builder.Services.AddHttpClient();

builder.Services.AddDataProtection();

builder.Services
    .AddOptions<BirdEmailOptions>()
    .BindConfiguration(BirdEmailOptions.SectionName)
    .Validate(options => !string.IsNullOrWhiteSpace(options.ApiKey), "Bird:ApiKey is required.")
    .Validate(options => !string.IsNullOrWhiteSpace(options.FromEmail), "Bird:FromEmail is required.")
    .Validate(options => !string.IsNullOrWhiteSpace(options.BaseUrl), "Bird:BaseUrl is required.")
    .Validate(options => !string.IsNullOrWhiteSpace(options.PublicApiBaseUrl), "Bird:PublicApiBaseUrl is required.")
    .ValidateOnStart();

builder.Services.AddDbContext<AuthDbContext>(options =>
    options.UseSqlite(
        builder.Configuration.GetConnectionString("AuthDb")
        ?? "Data Source=authman.db")
        .UseOpenIddict());

builder.Services
    .AddDefaultIdentity<IdentityUser>(options =>
    {
        options.User.RequireUniqueEmail = true;
        options.SignIn.RequireConfirmedEmail = true;
    })
    .AddEntityFrameworkStores<AuthDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
            .UseDbContext<AuthDbContext>();
    })
    .AddServer(options =>
    {
        var configuredIssuer = builder.Configuration["OpenIddict:Issuer"];
        if (!builder.Environment.IsDevelopment() &&
            (!Uri.TryCreate(configuredIssuer, UriKind.Absolute, out var productionIssuer) ||
             productionIssuer.Scheme != Uri.UriSchemeHttps))
        {
            throw new InvalidOperationException(
                "Production requires OpenIddict:Issuer to be an absolute HTTPS URL.");
        }

        var issuer = configuredIssuer ?? "https://localhost:7003/";
        options.SetIssuer(new Uri(issuer));
        options.SetAuthorizationEndpointUris("/connect/authorize");
        options.SetTokenEndpointUris("/connect/token");
        options.AllowAuthorizationCodeFlow();
        options.RequireProofKeyForCodeExchange();
        options.RegisterScopes(
            OpenIddictConstants.Scopes.Email,
            OpenIddictConstants.Scopes.Profile);

        if (builder.Environment.IsDevelopment())
        {
            options.AddDevelopmentEncryptionCertificate()
                .AddDevelopmentSigningCertificate();
        }
        else
        {
            var signingCertificatePath = builder.Configuration["OpenIddict:SigningCertificatePath"];
            var encryptionCertificatePath = builder.Configuration["OpenIddict:EncryptionCertificatePath"];
            if (string.IsNullOrWhiteSpace(signingCertificatePath) ||
                string.IsNullOrWhiteSpace(encryptionCertificatePath))
            {
                throw new InvalidOperationException(
                    "Production requires OpenIddict:SigningCertificatePath and OpenIddict:EncryptionCertificatePath.");
            }

            options.AddSigningCertificate(X509CertificateLoader.LoadPkcs12FromFile(
                signingCertificatePath,
                builder.Configuration["OpenIddict:SigningCertificatePassword"]));
            options.AddEncryptionCertificate(X509CertificateLoader.LoadPkcs12FromFile(
                encryptionCertificatePath,
                builder.Configuration["OpenIddict:EncryptionCertificatePassword"]));
        }

        options.UseAspNetCore()
            .EnableAuthorizationEndpointPassthrough()
            .EnableTokenEndpointPassthrough();
    });

builder.Services.AddTransient<IEmailSender, BirdEmailSender>();

builder.Services.AddAuthorization();

var app = builder.Build();

await using (var scope = app.Services.CreateAsyncScope())
{
    var database = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
    if (app.Environment.IsDevelopment())
    {
        await database.Database.MigrateAsync();
    }

    var applicationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
    foreach (var clientConfiguration in builder.Configuration
        .GetSection("OpenIddict:Clients")
        .GetChildren())
    {
        var clientId = clientConfiguration["ClientId"];
        if (string.IsNullOrWhiteSpace(clientId) ||
            await applicationManager.FindByClientIdAsync(clientId) is not null)
        {
            continue;
        }

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            DisplayName = clientConfiguration["DisplayName"],
            ClientType = OpenIddictConstants.ClientTypes.Public
        };

        foreach (var redirectUri in clientConfiguration
            .GetSection("RedirectUris")
            .Get<string[]>() ?? [])
        {
            descriptor.RedirectUris.Add(new Uri(redirectUri));
        }

        foreach (var permission in new[]
        {
            OpenIddictConstants.Permissions.Endpoints.Authorization,
            OpenIddictConstants.Permissions.Endpoints.Token,
            OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
            OpenIddictConstants.Permissions.ResponseTypes.Code,
            OpenIddictConstants.Permissions.Scopes.Email,
            OpenIddictConstants.Permissions.Scopes.Profile,
            OpenIddictConstants.Permissions.Prefixes.Scope + OpenIddictConstants.Scopes.OpenId
        })
        {
            descriptor.Permissions.Add(permission);
        }

        descriptor.Requirements.Add(
            OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange);

        await applicationManager.CreateAsync(descriptor);
    }
}

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.UseSwaggerUI(options =>
    {
        options.SwaggerEndpoint("/openapi/v1.json", "AuthMan API v1");
        options.RoutePrefix = "swagger";
    });
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseRateLimiter();
app.UseAuthorization();
app.MapControllers();
app.MapRazorPages();

app.Run();

public partial class Program { }