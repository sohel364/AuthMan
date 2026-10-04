using AuthMan.Api.Data;
using AuthMan.Api.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
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


builder.Services.AddDataProtection();

builder.Services
    .AddOptions<EmailOptions>()
    .BindConfiguration(EmailOptions.SectionName)
    .Validate(options => !string.IsNullOrWhiteSpace(options.Host), "Email:Host is required.")
    .Validate(options => options.Port is > 0 and <= 65535, "Email:Port must be between 1 and 65535.")
    .Validate(options => !string.IsNullOrWhiteSpace(options.FromAddress), "Email:FromAddress is required.")
    .Validate(
        options => builder.Environment.IsDevelopment() || options.UseSsl || options.UseStartTls,
        "SMTP must use SSL or STARTTLS outside Development.")
    .Validate(options =>
    {
        if (!Uri.TryCreate(options.PublicApiBaseUrl, UriKind.Absolute, out var uri))
        {
            return false;
        }

        return uri.Scheme is "http" or "https";
    }, "Email:PublicApiBaseUrl must be an absolute HTTP or HTTPS URL.")
    .Validate(options =>
        string.IsNullOrWhiteSpace(options.UserName) == string.IsNullOrWhiteSpace(options.Password),
        "Email:UserName and Email:Password must either both be set or both be empty.")
    .ValidateOnStart();

builder.Services.AddDbContext<AuthDbContext>(options =>
    options.UseSqlite(
        builder.Configuration.GetConnectionString("AuthDb")
        ?? "Data Source=authman.db"));

builder.Services
    .AddIdentityCore<IdentityUser>(options =>
    {
        options.User.RequireUniqueEmail = true;
        options.SignIn.RequireConfirmedEmail = true;
    })
    .AddEntityFrameworkStores<AuthDbContext>()
    .AddSignInManager()
    .AddDefaultTokenProviders();

builder.Services.AddTransient<IEmailSender, SmtpEmailSender>();

builder.Services.AddAuthorization();

var app = builder.Build();

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
app.UseRateLimiter();
app.UseAuthorization();
app.MapControllers();

app.Run();

public partial class Program { }