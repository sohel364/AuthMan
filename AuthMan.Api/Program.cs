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

builder.Services.AddTransient<IEmailSender, BirdEmailSender>();

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