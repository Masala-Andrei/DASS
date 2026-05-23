using AuthX.Vulnerable.Data;
using AuthX.Vulnerable.Models;
using AuthX.Vulnerable.Services;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppDbContext>(opt =>
    opt.UseSqlite(builder.Configuration.GetConnectionString("Default")));

builder.Services.AddScoped<CurrentUserService>();

builder.Services.AddControllersWithViews();
builder.Services.AddHttpContextAccessor();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.EnsureCreated();

    if (!db.Users.Any())
    {
        db.Users.AddRange(
            new User
            {
                Email = "alice@authx.local",
                Password = "password123",
                Role = "ANALYST"
            },
            new User
            {
                Email = "bob@authx.local",
                Password = "qwerty",
                Role = "ANALYST"
            },
            new User
            {
                Email = "manager@authx.local",
                Password = "manager",
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

app.UseStaticFiles();

app.UseRouting();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
