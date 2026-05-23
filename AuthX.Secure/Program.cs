using AuthX.Secure.Data;
using AuthX.Secure.Models;
using AuthX.Secure.Services;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppDbContext>(opt =>
    opt.UseSqlite(builder.Configuration.GetConnectionString("Default")));

builder.Services.AddSingleton<PasswordHasher>();
builder.Services.AddSingleton<PasswordPolicy>();
builder.Services.AddScoped<SessionService>();
builder.Services.AddScoped<CurrentUserService>();

// FIX (BONUS CSRF): cookie-ul de antiforgery e si el HttpOnly + Secure (cand e HTTPS) + Strict.
builder.Services.AddAntiforgery(o =>
{
    o.Cookie.HttpOnly = true;
    o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    o.Cookie.SameSite = SameSiteMode.Strict;
});

builder.Services.AddControllersWithViews();
builder.Services.AddHttpContextAccessor();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.EnsureCreated();

    if (!db.Users.Any())
    {
        var hasher = scope.ServiceProvider.GetRequiredService<PasswordHasher>();
        // Conturi de test cu parole care respecta politica (>=12, complexitate completa).
        db.Users.AddRange(
            new User
            {
                Email = "alice@authx.local",
                PasswordHash = hasher.Hash("Alice!Strong#2026"),
                Role = "ANALYST"
            },
            new User
            {
                Email = "bob@authx.local",
                PasswordHash = hasher.Hash("Bob!Secure#Pwd2026"),
                Role = "ANALYST"
            },
            new User
            {
                Email = "manager@authx.local",
                PasswordHash = hasher.Hash("Manager!Boss#2026"),
                Role = "MANAGER"
            }
        );
        db.SaveChanges();

        var alice = db.Users.First(u => u.Email == "alice@authx.local");
        var bob = db.Users.First(u => u.Email == "bob@authx.local");
        var manager = db.Users.First(u => u.Email == "manager@authx.local");

        db.Tickets.AddRange(
            new Ticket
            {
                Title = "Resetare parola pentru cont",
                Description = "Userul a uitat parola, are nevoie de reset.",
                Severity = "LOW",
                Status = "OPEN",
                OwnerId = alice.Id
            },
            new Ticket
            {
                Title = "Suspect phishing email pe inbox",
                Description = "Email cu link suspect catre login fals. Detalii confidentiale in interior.",
                Severity = "HIGH",
                Status = "OPEN",
                OwnerId = bob.Id
            },
            new Ticket
            {
                Title = "Audit acces server productie",
                Description = "Lista de useri care au accesat serverul prod in ultima saptamana.",
                Severity = "MEDIUM",
                Status = "IN_PROGRESS",
                OwnerId = manager.Id
            }
        );
        db.SaveChanges();
    }
}

// FIX: redirectionare HTTPS in productie.
if (!app.Environment.IsDevelopment())
{
    app.UseHttpsRedirection();
    app.UseHsts();
}

app.UseStaticFiles();
app.UseRouting();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
