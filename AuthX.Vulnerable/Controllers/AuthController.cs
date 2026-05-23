using AuthX.Vulnerable.Data;
using AuthX.Vulnerable.Models;
using AuthX.Vulnerable.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthX.Vulnerable.Controllers;

public class AuthController : Controller
{
    private readonly AppDbContext _db;

    public AuthController(AppDbContext db)
    {
        _db = db;
    }


    [HttpGet]
    public IActionResult Register() => View(new RegisterViewModel());

   
    [HttpPost]
    public async Task<IActionResult> Register(RegisterViewModel vm)
    {
        if (string.IsNullOrWhiteSpace(vm.Email) || string.IsNullOrWhiteSpace(vm.Password))
        {
            ViewBag.Error = "Email si parola sunt obligatorii.";
            return View(vm);
        }

        // Eroare specifica pentru user care nu exista (user enumemration)
        var exists = await _db.Users.AnyAsync(u => u.Email == vm.Email);
        if (exists)
        {
            ViewBag.Error = $"Emailul {vm.Email} este deja inregistrat.";
            return View(vm);
        }

        // Parola este stocata in clar
        var user = new User
        {
            Email = vm.Email,
            Password = vm.Password,
            Role = string.IsNullOrWhiteSpace(vm.Role) ? "USER" : vm.Role,
            CreatedAt = DateTime.UtcNow,
            Locked = false
        };

        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        _db.AuditLogs.Add(new AuditLog
        {
            UserId = user.Id,
            Action = "REGISTER",
            Resource = "auth",
            ResourceId = user.Id.ToString(),
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString()
        });
        await _db.SaveChangesAsync();

        TempData["Info"] = $"Cont creat cu succes pentru {user.Email}. Te poti loga.";
        return RedirectToAction(nameof(Login));
    }


    [HttpGet]
    public IActionResult Login() => View(new LoginViewModel());

    // Nu am rate limiting pentru login, deci merge brute force
    [HttpPost]
    public async Task<IActionResult> Login(LoginViewModel vm)
    {
        // Nu verific in niciun fel inputul deci este psibil un sql injection
        var rawSql = $"SELECT * FROM Users WHERE Email = '{vm.Email}'";
        User? user;
        try
        {
            user = await _db.Users.FromSqlRaw(rawSql).FirstOrDefaultAsync();
        }
        catch (Exception ex)
        {
            ViewBag.Error = "Eroare DB: " + ex.Message;
            return View(vm);
        }

        // Alta instanta de user enumeration
        if (user == null)
        {
            ViewBag.Error = "User inexistent.";
            return View(vm);
        }

        // Parola nu are niciun fel de validare (orice parola e acceptata)
        if (user.Password != vm.Password)
        {
            _db.AuditLogs.Add(new AuditLog
            {
                UserId = user.Id,
                Action = "LOGIN_FAILED",
                Resource = "auth",
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString()
            });
            await _db.SaveChangesAsync();
            // Si inca unul de user enumeration
            ViewBag.Error = "Parola gresita."; 
            return View(vm);
        }

        // Cookie-ului e doar ID-ul userului 
        SessionCookie.Set(HttpContext, user.Id);

        _db.AuditLogs.Add(new AuditLog
        {
            UserId = user.Id,
            Action = "LOGIN_SUCCESS",
            Resource = "auth",
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString()
        });
        await _db.SaveChangesAsync();

        return RedirectToAction("Index", "Tickets");
    }


    // La delogare, cookie-ul este pur si simplu sters din browserul clientului, fara sa fie invalidat
    // pe server, daca cineva are deja cookie-ul poate continua sesiunea
    [HttpPost]
    public IActionResult Logout()
    {
        SessionCookie.Clear(HttpContext);
        TempData["Info"] = "Te-ai delogat.";
        return RedirectToAction(nameof(Login));
    }


    [HttpGet]
    public IActionResult ForgotPassword() => View(new ForgotPasswordViewModel());



    // La token-ul de reset, acesta este predictibil (email + cuvant), nici nu expira si este reutilizabil
    [HttpPost]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel vm)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == vm.Email);
        if (user == null)
        {
            // Alt user enumeration
            ViewBag.Error = "Nu exista cont cu acest email.";
            return View(vm);
        }

        var predictableToken = user.Email + "RESET";

        _db.PasswordResetTokens.Add(new PasswordResetToken
        {
            UserId = user.Id,
            Token = predictableToken,
            CreatedAt = DateTime.UtcNow,
            Used = false
        });
        await _db.SaveChangesAsync();

        ViewBag.Token = predictableToken;
        ViewBag.Email = user.Email;
        return View(vm);
    }


    [HttpGet]
    public IActionResult ResetPassword(string? token)
    {
        return View(new ResetPasswordViewModel { Token = token ?? string.Empty });
    }

    // Din nou, nu verific daca tokenul a expirat sau daca a fost deja folosit
    [HttpPost]
    public async Task<IActionResult> ResetPassword(ResetPasswordViewModel vm)
    {
        var record = await _db.PasswordResetTokens
            .Include(t => t.User)
            .FirstOrDefaultAsync(t => t.Token == vm.Token);

        if (record == null || record.User == null)
        {
            ViewBag.Error = "Token invalid.";
            return View(vm);
        }

        record.User.Password = vm.NewPassword;
        await _db.SaveChangesAsync();

        TempData["Info"] = $"Parola schimbata pentru {record.User.Email}. Te poti loga.";
        return RedirectToAction(nameof(Login));
    }
}
