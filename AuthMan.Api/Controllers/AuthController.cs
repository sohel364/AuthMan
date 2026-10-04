using System.ComponentModel.DataAnnotations;
using System.Text;
using System.Text.Encodings.Web;
using AuthMan.Api.Services;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;

namespace AuthMan.Api.Controllers;

[ApiController]
[Route("api/auth")]
public sealed class AuthController(
    UserManager<IdentityUser> userManager,
    IEmailSender emailSender,
    IOptions<EmailOptions> emailOptions) : ControllerBase
{
    [HttpPost("register")]
    [EnableRateLimiting("registration")]
    [ProducesResponseType(StatusCodes.Status202Accepted)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Register(
        RegisterRequest request,
        CancellationToken cancellationToken)
    {
        var user = new IdentityUser
        {
            UserName = request.Email,
            Email = request.Email
        };

        var createResult = await userManager.CreateAsync(user, request.Password);

        if (!createResult.Succeeded)
        {
            var isDuplicate = createResult.Errors.Any(error =>
                error.Code is "DuplicateEmail" or "DuplicateUserName");

            if (isDuplicate)
            {
                var existingUser = await userManager.FindByEmailAsync(request.Email);
                if (existingUser is not null && !existingUser.EmailConfirmed)
                {
                    await SendConfirmationAsync(existingUser, cancellationToken);
                }

                // Avoid revealing whether an account with this email already exists.
                return Accepted(new
                {
                    message = "If registration can be completed, a confirmation message will be sent."
                });
            }

            return BadRequest(new
            {
                errors = createResult.Errors.Select(error => error.Code)
            });
        }

        await SendConfirmationAsync(user, cancellationToken);

        return Accepted(new
        {
            message = "If registration can be completed, a confirmation message will be sent."
        });
    }

    [HttpGet("verify-email-link")]
    [Produces("text/html")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public IActionResult ShowEmailVerification(
        [FromQuery, Required, EmailAddress] string email,
        [FromQuery, Required] string token)
    {
        var safeEmail = HtmlEncoder.Default.Encode(email);
        var safeToken = HtmlEncoder.Default.Encode(token);
        var page = $"""
            <!doctype html>
            <html lang="en">
            <head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Confirm email</title></head>
            <body>
              <main>
                <h1>Confirm your email</h1>
                <p>Confirm the email address {safeEmail} for your AuthMan account.</p>
                <form method="post" action="/api/auth/verify-email-link">
                  <input type="hidden" name="email" value="{safeEmail}">
                  <input type="hidden" name="token" value="{safeToken}">
                  <button type="submit">Confirm email</button>
                </form>
              </main>
            </body>
            </html>
            """;

        return Content(page, "text/html; charset=utf-8");
    }

    [HttpPost("verify-email-link")]
    [Consumes("application/x-www-form-urlencoded")]
    [Produces("text/html")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> VerifyEmailLink(
        [FromForm] VerifyEmailLinkRequest request)
    {
        string token;
        try
        {
            token = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(request.Token));
        }
        catch (FormatException)
        {
            return VerificationResultPage(false);
        }

        var user = await userManager.FindByEmailAsync(request.Email);
        if (user is null)
        {
            return VerificationResultPage(false);
        }

        if (!user.EmailConfirmed)
        {
            var result = await userManager.ConfirmEmailAsync(user, token);
            if (!result.Succeeded)
            {
                return VerificationResultPage(false);
            }
        }

        return VerificationResultPage(true);
    }

    [HttpPost("verify-email")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> VerifyEmail(VerifyEmailRequest request)
    {
        var user = await userManager.FindByEmailAsync(request.Email);

        if (user is null)
        {
            return BadRequest(new { error = "Invalid or expired confirmation token." });
        }

        if (user.EmailConfirmed)
        {
            return NoContent();
        }

        var confirmResult = await userManager.ConfirmEmailAsync(user, request.Token);

        if (!confirmResult.Succeeded)
        {
            return BadRequest(new { error = "Invalid or expired confirmation token." });
        }

        return NoContent();
    }

    public sealed class RegisterRequest
    {
        [Required, EmailAddress]
        public string Email { get; init; } = string.Empty;

        [Required, MinLength(8)]
        public string Password { get; init; } = string.Empty;
    }

    public sealed class VerifyEmailRequest
    {
        [Required, EmailAddress]
        public string Email { get; init; } = string.Empty;

        [Required]
        public string Token { get; init; } = string.Empty;
    }

    public sealed class VerifyEmailLinkRequest
    {
        [Required, EmailAddress]
        public string Email { get; init; } = string.Empty;

        [Required]
        public string Token { get; init; } = string.Empty;
    }

    private async Task SendConfirmationAsync(
        IdentityUser user,
        CancellationToken cancellationToken)
    {
        var token = await userManager.GenerateEmailConfirmationTokenAsync(user);
        var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
        var baseUrl = emailOptions.Value.PublicApiBaseUrl.TrimEnd('/');
        var confirmationLink = QueryHelpers.AddQueryString(
            $"{baseUrl}/api/auth/verify-email-link",
            new Dictionary<string, string?>
            {
                ["email"] = user.Email,
                ["token"] = encodedToken
            });

        await emailSender.SendConfirmationAsync(
            user.Email!,
            confirmationLink,
            cancellationToken);
    }

    private ContentResult VerificationResultPage(bool confirmed)
    {
        var heading = confirmed ? "Email confirmed" : "Confirmation link invalid or expired";
        var message = confirmed
            ? "Your AuthMan email address is confirmed. You can close this page."
            : "This confirmation link is invalid or expired. Request a new confirmation email.";
        var statusCode = confirmed
            ? StatusCodes.Status200OK
            : StatusCodes.Status400BadRequest;

        return new ContentResult
        {
            Content = $"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>{heading}</title></head><body><main><h1>{heading}</h1><p>{message}</p></main></body></html>",
            ContentType = "text/html; charset=utf-8",
            StatusCode = statusCode
        };
    }
}
