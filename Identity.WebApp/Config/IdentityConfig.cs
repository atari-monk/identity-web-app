using Identity.WebApp.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Identity.WebApp.Config;

public class IdentityConfig
{
    private readonly WebApplicationBuilder builder;

    public IdentityConfig(WebApplicationBuilder builder)
    {
        this.builder = builder;
    }

    public void RegisterServices()
    {
        SetIdentityDb();
        SetDefaultIdentity();
        SetIdentityOptions();
        SetCookieSettings();
        SetAuthorization();
    }

    private void SetIdentityDb()
    {
        var connectionString = builder.Configuration.GetConnectionString("IdentityDataContextConnection")
                    ?? throw new InvalidOperationException("Connection string 'IdentityDataContextConnection' not found.");

        builder.Services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(connectionString));
    }

    private void SetDefaultIdentity()
    {
        builder.Services.AddDefaultIdentity<IdentityUser>(options =>
            options.SignIn.RequireConfirmedAccount = true)
                .AddRoles<IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>();
    }

    private void SetIdentityOptions()
    {
        builder.Services.Configure((Action<IdentityOptions>)(options =>
        {
            SetPasswordSettings(options);
            SetLockoutSettings(options);
            SetUserSettings(options);
        }));
    }

    private static void SetPasswordSettings(IdentityOptions options)
    {
        options.Password.RequireDigit = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireNonAlphanumeric = true;
        options.Password.RequireUppercase = true;
        options.Password.RequiredLength = 6;
        options.Password.RequiredUniqueChars = 1;
    }

    private static void SetLockoutSettings(IdentityOptions options)
    {
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.AllowedForNewUsers = true;
    }

    private static void SetUserSettings(IdentityOptions options)
    {
        options.User.AllowedUserNameCharacters =
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
        options.User.RequireUniqueEmail = false;
    }

    private void SetCookieSettings()
    {
        builder.Services.ConfigureApplicationCookie(options =>
        {
            // Cookie settings
            options.Cookie.HttpOnly = true;
            options.ExpireTimeSpan = TimeSpan.FromHours(2);

            options.LoginPath = "/Identity/Account/Login";
            options.AccessDeniedPath = "/Identity/Account/AccessDenied";
            options.SlidingExpiration = true;
        });
    }

    private void SetAuthorization()
    {
        builder.Services.AddAuthorization(options =>
        {
            options.AddPolicy("RequireAdministratorRole",
                policy => policy.RequireRole("Administrator"));
        });
    }
}