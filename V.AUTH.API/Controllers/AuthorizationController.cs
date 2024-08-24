using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using V.AUTH.API.Models;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace V.AUTH.API.Controllers
{
    [Route("connect")]
    public class AuthorizationController : Controller
    {
        private readonly SignInManager<AuthUser> _signInManager;
        private readonly UserManager<AuthUser> _userManager;
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly IOpenIddictAuthorizationManager _authorizationManager;
        private readonly IOpenIddictTokenManager _tokenManager;

        public AuthorizationController(
            SignInManager<AuthUser> signInManager,
            UserManager<AuthUser> userManager,
            IOpenIddictApplicationManager applicationManager,
            IOpenIddictAuthorizationManager authorizationManager,
            IOpenIddictTokenManager tokenManager)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _applicationManager = applicationManager;
            _authorizationManager = authorizationManager;
            _tokenManager = tokenManager;
        }

        #region /connect/authorize
        [HttpGet("authorize")]
        public async Task<IActionResult> Authorize()
        {
            var request = HttpContext.GetOpenIddictServerRequest();

            // Validate request and render the consent/login form
            if (!User?.Identity?.IsAuthenticated ?? false)
            {
                // Redirect the user to the login page if not authenticated
                return Challenge();
            }

            // Render the consent form to the user
            // Implement your consent UI here
            return View();  // Provide a view that asks the user to approve the request
        }

        [HttpPost("authorize")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> AuthorizePost()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ?? throw new NullReferenceException("Request was null");

            if (!User?.Identity?.IsAuthenticated ?? false)
            {
                return Challenge();
            }

            // Extract the authorization request
            var principal = new ClaimsPrincipal(User ?? throw new NullReferenceException("User was null"));
            principal.SetScopes(request.GetScopes());
            principal.SetResources("api");

            // Add more claims or process as needed

            // Sign in the user and issue tokens
            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }
        #endregion

        #region /connect/token
        [HttpPost("token"), Produces("application/json")]
        public async Task<IActionResult> Exchange()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ?? throw new NullReferenceException("Request was null");

            if (request.IsAuthorizationCodeGrantType() || request.IsImplicitFlow())
            {
                // Validate the code/credentials and return tokens
                return SignIn(User, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            if (request.IsPasswordGrantType())
            {
                var user = await _userManager.FindByNameAsync(request.Username ?? throw new NullReferenceException("Username was null"));
                if (user == null || !await _userManager.CheckPasswordAsync(user, request.Password ?? throw new NullReferenceException("Password was null")))
                {
                    return Forbid();
                }

                var principal = await _signInManager.CreateUserPrincipalAsync(user);
                principal.SetScopes(request.GetScopes());
                principal.SetResources("api");

                return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            if (request.IsClientCredentialsGrantType())
            {
                var application = await _applicationManager.FindByClientIdAsync(request.ClientId ?? throw new NullReferenceException("ClientId was null"));
                if (application == null)
                {
                    return BadRequest(new { error = "Invalid client_id" });
                }

                var principal = new ClaimsPrincipal(
                    new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType));
                principal.SetScopes(request.GetScopes());
                principal.SetResources("api");

                return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            return BadRequest();
        }
        #endregion

        #region /connect/userinfo
        [HttpGet("userinfo")]
        public async Task<IActionResult> UserInfo()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return Challenge(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            var claims = new Dictionary<string, object>
            {
                [Claims.Subject] = await _userManager.GetUserIdAsync(user),
                [Claims.Name] = await _userManager.GetUserNameAsync(user) ?? "Unknown",
                [Claims.Role] = await _userManager.GetRolesAsync(user)
                // Add additional claims as needed
            };

            return Ok(claims);
        }
        #endregion

        #region /connect/introspect
        [HttpPost("introspect")]
        public async Task<IActionResult> Introspect()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ?? throw new NullReferenceException("Request was null");

            var token = await _tokenManager.FindByReferenceIdAsync(request.Token ?? throw new NullReferenceException("Token was null"));
            if (token == null)
            {
                return BadRequest(new { active = false });
            }

            var result = new
            {
                active = true,
            };

            return Ok(result);
        }
        #endregion

        #region /connect/revocation
        [HttpPost("revocation")]
        public async Task<IActionResult> Revoke()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ?? throw new NullReferenceException("Request was null");

            var token = await _tokenManager.FindByReferenceIdAsync(request.Token ?? throw new NullReferenceException("Token was null"));
            if (token == null)
            {
                return BadRequest(new { error = "Invalid token" });
            }

            var result = await _tokenManager.TryRevokeAsync(token);
            if (!result)
            {
                return BadRequest(new { error = "Failed to revoke the token" });
            }

            return Ok();
        }
        #endregion
    }
}
