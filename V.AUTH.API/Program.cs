using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Validation.AspNetCore;
using Serilog;
using System.Security.Cryptography.X509Certificates;
using V.AUTH.API.Database;
using V.AUTH.API.Models;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);

// Configure Serilog
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .Enrich.FromLogContext()
    .WriteTo.Console()
    .WriteTo.File("logs/log-.txt", rollingInterval: RollingInterval.Day)
    .CreateLogger();

builder.Host.UseSerilog();

// Add the DbContext and configure ASP.NET Core Identity
builder.Services.AddDbContext<AuthDbContext>(options =>
{
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection"));
    options.UseOpenIddict(); // Add OpenIddict support for EF Core
});

builder.Services.AddIdentity<AuthUser, IdentityRole>()
    .AddEntityFrameworkStores<AuthDbContext>()
    .AddDefaultTokenProviders();

// Configure OpenIddict
var identityServerBuilder = builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        // Register the Entity Framework Core stores and models.
        options.UseEntityFrameworkCore()
               .UseDbContext<AuthDbContext>();
    })
    .AddServer(options =>
    {
        // Enable the authorization, token, userinfo, introspection, and revocation endpoints.
        options.SetAuthorizationEndpointUris("/connect/authorize")
               .SetTokenEndpointUris("/connect/token")
               .SetUserinfoEndpointUris("/connect/userinfo")
               .SetIntrospectionEndpointUris("/connect/introspect")
               .SetRevocationEndpointUris("/connect/revocation");

        // Enable the different flows.
        options.AllowAuthorizationCodeFlow()
               .AllowImplicitFlow()
               .RequireProofKeyForCodeExchange()
               .AllowClientCredentialsFlow()
               .AllowRefreshTokenFlow();

        // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
        options.UseAspNetCore()
               .EnableAuthorizationEndpointPassthrough()
               .EnableTokenEndpointPassthrough()
               .EnableUserinfoEndpointPassthrough();

        if (builder.Environment.IsDevelopment())
        {
            // Use development certificates in development.
            options.AddDevelopmentEncryptionCertificate()
                   .AddDevelopmentSigningCertificate();
        }
        else
        {
            // Use a production certificate in production.
            var keyMaterialConfig = builder.Configuration.GetSection("IdentityServer:KeyMaterial");
            var certPath = keyMaterialConfig.GetValue<string>("Certificate:Path");
            var certPassword = keyMaterialConfig.GetValue<string>("Certificate:Password");

            if (!string.IsNullOrEmpty(certPath))
            {
                var certificate = new X509Certificate2(certPath, certPassword);
                options.AddEncryptionCertificate(certificate)
                       .AddSigningCertificate(certificate); // Use the signing certificate
            }
            else
            {
                throw new InvalidOperationException("Signing and encryption certificate configuration is missing or invalid.");
            }
        }
    })
    .AddValidation(options =>
    {
        // Register the ASP.NET Core host.
        options.UseAspNetCore();
        options.UseLocalServer();
    });

// Configure JWT Bearer Authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
});

builder.Services.AddControllers();

// Add Swagger/OpenAPI support
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseSwagger();
    app.UseSwaggerUI();

    // Seed the test user and clients
    using (var scope = app.Services.CreateScope())
    {
        var services = scope.ServiceProvider;
        var userManager = services.GetRequiredService<UserManager<AuthUser>>();
        var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
        var applicationManager = services.GetRequiredService<IOpenIddictApplicationManager>();
        await SeedTestUser(userManager, roleManager);
        await SeedClients(applicationManager);
    }
}

app.UseHttpsRedirection();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

try
{
    Log.Information("Starting up the application");
    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "The application failed to start correctly");
    throw;
}
finally
{
    Log.CloseAndFlush(); // Ensure all logs are flushed before the application shuts down
}

async Task SeedTestUser(UserManager<AuthUser> userManager, RoleManager<IdentityRole> roleManager)
{
    var testUserEmail = "testuser@example.com";
    var testUserPassword = "Test@1234";

    // Create an admin role if it doesn't exist
    if (!await roleManager.RoleExistsAsync("Admin"))
    {
        await roleManager.CreateAsync(new IdentityRole("Admin"));
    }

    // Check if the test user already exists
    var user = await userManager.FindByEmailAsync(testUserEmail);
    if (user == null)
    {
        // Create the test user
        user = new AuthUser
        {
            UserName = "testuser",
            Email = testUserEmail,
            FirstName = "Test",
            LastName = "User"
        };

        var result = await userManager.CreateAsync(user, testUserPassword);
        if (result.Succeeded)
        {
            // Assign the user to the admin role
            await userManager.AddToRoleAsync(user, "Admin");
        }
    }
}

async Task SeedClients(IOpenIddictApplicationManager applicationManager)
{
    if (await applicationManager.FindByClientIdAsync("your-client-id") == null)
    {
        await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "your-client-id",
            ClientSecret = "your-client-secret",
            DisplayName = "Your Client Application",
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                OpenIddictConstants.Permissions.ResponseTypes.Code,

                // Include the general scope permission
                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Scopes.Roles,
            }
        });
    }
}




