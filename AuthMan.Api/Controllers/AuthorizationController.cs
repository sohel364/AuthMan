using System.Security.Claims;
using AuthMan.Api.Services;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace AuthMan.Api.Controllers;

public sealed class AuthorizationController(
    UserManager<IdentityUser> userManager) : Controller
{
    [AcceptVerbs("GET", "POST")]
    [Route("~/connect/authorize")]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        var authentication = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        if (!authentication.Succeeded)
        {
            return Challenge(
                new AuthenticationProperties
                {
                    RedirectUri = Request.PathBase + Request.Path + Request.QueryString
                },
                IdentityConstants.ApplicationScheme);
        }

        var user = await userManager.GetUserAsync(authentication.Principal!);
        if (user is null || !user.EmailConfirmed)
        {
            return Forbid(IdentityConstants.ApplicationScheme);
        }

        var identity = new ClaimsIdentity(
            TokenValidationParameters.DefaultAuthenticationType,
            OpenIddictConstants.Claims.Name,
            OpenIddictConstants.Claims.Role);

        identity.SetClaim(OpenIddictConstants.Claims.Subject, user.Id);
        identity.SetClaim(OpenIddictConstants.Claims.Email, user.Email);
        identity.SetClaim(OpenIddictConstants.Claims.EmailVerified, user.EmailConfirmed);
        identity.SetClaim(OpenIddictConstants.Claims.Name, user.UserName);
        identity.SetScopes(request.GetScopes());
        identity.SetDestinations(static claim => claim.Type switch
        {
            OpenIddictConstants.Claims.Email when claim.Subject!.HasScope(OpenIddictConstants.Scopes.Email) =>
            [OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken],
            OpenIddictConstants.Claims.EmailVerified when claim.Subject!.HasScope(OpenIddictConstants.Scopes.Email) =>
            [OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken],
            OpenIddictConstants.Claims.Name when claim.Subject!.HasScope(OpenIddictConstants.Scopes.Profile) =>
            [OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken],
            _ => [OpenIddictConstants.Destinations.AccessToken]
        });

        return SignIn(
            new ClaimsPrincipal(identity),
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpPost("~/connect/token")]
    [Produces("application/json")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (!request.IsAuthorizationCodeGrantType())
        {
            return BadRequest(new { error = "unsupported_grant_type" });
        }

        var authentication = await HttpContext.AuthenticateAsync(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var subject = authentication.Principal?.GetClaim(OpenIddictConstants.Claims.Subject);
        var user = subject is null ? null : await userManager.FindByIdAsync(subject);

        if (user is null || !user.EmailConfirmed)
        {
            return Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        return SignIn(
            authentication.Principal!,
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
}