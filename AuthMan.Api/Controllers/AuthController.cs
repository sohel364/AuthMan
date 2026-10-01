using System.ComponentModel.DataAnnotations;
using AuthMan.Api.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthMan.Api.Controllers;

[ApiController]
[Route("api/auth")]
public sealed class AuthController(
    UserManager<IdentityUser> userManager,
    IEmailSender emailSender) : ControllerBase
{
    [HttpPost("register")]
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

        var token = await userManager.GenerateEmailConfirmationTokenAsync(user);
        await emailSender.SendConfirmationAsync(
            user.Email!,
            token,
            cancellationToken);

        return Accepted(new
        {
            message = "If registration can be completed, a confirmation message will be sent."
        });
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
}
