using System.Diagnostics;
using AuthX.Secure.Data;
using AuthX.Secure.Models;
using AuthX.Secure.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthX.Secure.Controllers;

public class AuthController : Controller
{
    private readonly AppDbContext _db;
    private readonly PasswordHasher _hasher;
    private readonly PasswordPolicy _policy;
    private readonly SessionService _sessions;
    private readonly IConfiguration _config;
    private readonly ILogger<AuthController> _log;

    public AuthController(
        AppDbContext db,
        PasswordHasher hasher,
        PasswordPolicy policy,
        SessionService sessions,
        IConfiguration config,
        ILogger<AuthController> log)
    {
        _db = db;
        _hasher = hasher;
        _policy = policy;
        _sessions = sessions;
        _config = config;
        _log = log;
    }

    private static readonly string[] AllowedRoles = { "USER", "ANALYST", "MANAGER" };

    private int MaxFailedAttempts => _config.GetValue<int>("Security:MaxFailedAttempts", 5);
    private double LockoutMinutes => _config.GetValue<double>("Security:LockoutMinutes", 0.5);
    private int ResetTokenMinutes => _config.GetValue<int>("Security:ResetTokenMinutes", 15);


    [HttpGet]
    public IActionResult Register() => View(new RegisterViewModel());

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(RegisterViewModel vm)
    {
        // Validare mailului simpla
        if (string.IsNullOrWhiteSpace(vm.Email) || !vm.Email.Contains('@'))
        {
            ViewBag.Error = "Email invalid.";
            return View(vm);
        }

        if (!_policy.IsValid(vm.Password, out var policyError))
        {
            ViewBag.Error = policyError;
            return View(vm);
        }

        // Orice raspuns de register intoarce acelasi mesaj generic
        var exists = await _db.Users.AnyAsync(u => u.Email == vm.Email);
        if (!exists)
        {
            // Daca userul pune orice altcv in afara de user ca rol nu l lasam
            var role = AllowedRoles.Contains(vm.Role?.ToUpperInvariant()) ? vm.Role!.ToUpperInvariant() : "USER";

            var user = new User
            {
                Email = vm.Email,
                PasswordHash = _hasher.Hash(vm.Password),
                Role = role,
                CreatedAt = DateTime.UtcNow
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
        }

        TempData["Info"] = "Daca informatiile sunt valide, contul a fost creat. Te poti loga.";
        return RedirectToAction(nameof(Login));
    }


    [HttpGet]
    public IActionResult Login() => View(new LoginViewModel());

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel vm)
    {
        
        // Aprox 600 ms inainte sa raspundem, ca atacatorul sa nu poata distinge
        // "user inexistent" de "parola gresita" pe baza latency-ului.
        var sw = Stopwatch.StartNew();

        const string GenericError = "Email sau parola incorecta.";
        var minResponseMs = 600;

        try
        {
            // Intrarea utilizatorului nu se mai concateneaza in SQL.
            var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == vm.Email);

            // Rate limiting si lockout
            if (user != null)
            {
                if (user.LockedUntil.HasValue && user.LockedUntil.Value > DateTime.UtcNow)
                {
                    // Mesaj generic ca atacatroul sa nu stie ce s a intamplat
                    ViewBag.Error = GenericError;
                    return View(vm);
                }

                // Daca lockout ul a expirat, il resetez.
                if (user.LockedUntil.HasValue && user.LockedUntil.Value <= DateTime.UtcNow)
                {
                    user.LockedUntil = null;
                    user.FailedLoginAttempts = 0;
                }
            }

           
            // Compar parola cu bcrypt verify ca sa ruleze in timp constant. In plus daca user-ul nu exista, fac
            // verify pe un dummy ca sa fac acelasi timp de cpu
            bool ok;
            if (user == null)
            {
                _hasher.Verify(vm.Password, "$2a$12$abcdefghijklmnopqrstuvabcdefghijklmnopqrstuvwxyz0123");
                ok = false;
            }
            else
            {
                ok = _hasher.Verify(vm.Password, user.PasswordHash);
            }

            if (!ok)
            {
                if (user != null)
                {
                    user.FailedLoginAttempts++;
                    if (user.FailedLoginAttempts >= MaxFailedAttempts)
                    {
                        user.LockedUntil = DateTime.UtcNow.AddMinutes(LockoutMinutes);
                        // Resetam contorul ca dupa expirare sa o ia de la 0
                        user.FailedLoginAttempts = 0;
                        _log.LogWarning("Cont blocat temporar pentru user {UserId} dupa {N} incercari esuate", user.Id, MaxFailedAttempts);
                    }

                    _db.AuditLogs.Add(new AuditLog
                    {
                        UserId = user.Id,
                        Action = "LOGIN_FAILED",
                        Resource = "auth",
                        IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString()
                    });
                    await _db.SaveChangesAsync();
                }

                ViewBag.Error = GenericError;
                return View(vm);
            }

            user!.FailedLoginAttempts = 0;
            user.LockedUntil = null;
            await _db.SaveChangesAsync();

            await _sessions.CreateAsync(HttpContext, user);

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
        finally
        {
            sw.Stop();
            var remaining = minResponseMs - (int)sw.ElapsedMilliseconds;
            if (remaining > 0)
                await Task.Delay(remaining);
        }
    }


    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        // Revoc sesiunea server-side, plus sterg cookie-ul
        await _sessions.RevokeAsync(HttpContext);
        TempData["Info"] = "Te-ai delogat.";
        return RedirectToAction(nameof(Login));
    }


    [HttpGet]
    public IActionResult ForgotPassword() => View(new ForgotPasswordViewModel());

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel vm)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == vm.Email);

        if (user != null)
        {
            // Token random 32 bytes. In DB stochez doar hash-ul
            var raw = ResetTokenService.GenerateRawToken();
            var record = new PasswordResetToken
            {
                UserId = user.Id,
                TokenHash = ResetTokenService.Hash(raw),
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddMinutes(ResetTokenMinutes),
                Used = false
            };
            _db.PasswordResetTokens.Add(record);
            await _db.SaveChangesAsync();

            _log.LogInformation("[reset] token generat pentru {Email}: {Token} (expira {Expires:o})",
                user.Email, raw, record.ExpiresAt);

            TempData["LabResetToken"] = raw;
        }

        // Raspuns identic indiferent daca emailul exista sau nu
        TempData["Info"] = "Daca exista un cont cu acest email, am trimis instructiunile de resetare.";
        return RedirectToAction(nameof(ForgotPassword));
    }


    [HttpGet]
    public IActionResult ResetPassword(string? token)
    {
        return View(new ResetPasswordViewModel { Token = token ?? string.Empty });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResetPassword(ResetPasswordViewModel vm)
    {
        // Validez noua parola 
        if (!_policy.IsValid(vm.NewPassword, out var policyError))
        {
            ViewBag.Error = policyError;
            return View(vm);
        }

        if (string.IsNullOrEmpty(vm.Token))
        {
            ViewBag.Error = "Token invalid sau expirat.";
            return View(vm);
        }

        var hash = ResetTokenService.Hash(vm.Token);
        var record = await _db.PasswordResetTokens
            .Include(t => t.User)
            .FirstOrDefaultAsync(t => t.TokenHash == hash);

        if (record == null || record.User == null
            || record.Used
            || record.ExpiresAt < DateTime.UtcNow)
        {
            ViewBag.Error = "Token invalid sau expirat.";
            return View(vm);
        }

        record.User.PasswordHash = _hasher.Hash(vm.NewPassword);
        record.User.FailedLoginAttempts = 0;
        record.User.LockedUntil = null;

        // Marchez tokenul ca folosit si nu va mai putea fi folosit
        record.Used = true;
        record.UsedAt = DateTime.UtcNow;

        // Invalidez toate sesiunile active ale userului
        var sessions = _db.Sessions.Where(s => s.UserId == record.UserId);
        _db.Sessions.RemoveRange(sessions);

        await _db.SaveChangesAsync();

        TempData["Info"] = "Parola a fost schimbata. Te poti loga.";
        return RedirectToAction(nameof(Login));
    }
}
