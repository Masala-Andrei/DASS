using System.Security.Cryptography;
using AuthX.Secure.Data;
using AuthX.Secure.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthX.Secure.Services;


// Folosesc httponly + secure + samesite=strict
// cookie ul e generat random, nu mai e user ID
// Cand un user se logeaza, se sterge orice alta sesiune a suerului si creez una noua
public class SessionService
{
    public const string CookieName = "AUTHX_SESSION";

    private readonly AppDbContext _db;
    private readonly IConfiguration _config;

    public SessionService(AppDbContext db, IConfiguration config)
    {
        _db = db;
        _config = config;
    }

    private int SessionMinutes => _config.GetValue<int>("Security:SessionMinutes", 15);

    public async Task<Session> CreateAsync(HttpContext ctx, User user)
    {
        var old = _db.Sessions.Where(s => s.UserId == user.Id);
        _db.Sessions.RemoveRange(old);

        var session = new Session
        {
            Id = GenerateSessionId(),
            UserId = user.Id,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddMinutes(SessionMinutes),
            LastSeenAt = DateTime.UtcNow,
            UserAgent = ctx.Request.Headers["User-Agent"].ToString(),
            IpAddress = ctx.Connection.RemoteIpAddress?.ToString()
        };

        _db.Sessions.Add(session);
        await _db.SaveChangesAsync();

        WriteCookie(ctx, session.Id, session.ExpiresAt);
        return session;
    }

    public async Task RevokeAsync(HttpContext ctx)
    {
        var sid = ctx.Request.Cookies[CookieName];
        if (!string.IsNullOrEmpty(sid))
        {
            var s = await _db.Sessions.FirstOrDefaultAsync(x => x.Id == sid);
            if (s != null)
            {
                _db.Sessions.Remove(s);
                await _db.SaveChangesAsync();
            }
        }

        ctx.Response.Cookies.Delete(CookieName, new CookieOptions
        {
            HttpOnly = true,
            Secure = ctx.Request.IsHttps,
            SameSite = SameSiteMode.Strict,
            Path = "/"
        });
    }

    public async Task<Session?> ResolveAsync(HttpContext ctx)
    {
        var sid = ctx.Request.Cookies[CookieName];
        if (string.IsNullOrEmpty(sid)) return null;

        var s = await _db.Sessions
            .Include(x => x.User)
            .FirstOrDefaultAsync(x => x.Id == sid);

        if (s == null || s.Revoked) return null;
        if (s.ExpiresAt < DateTime.UtcNow)
        {
            _db.Sessions.Remove(s);
            await _db.SaveChangesAsync();
            return null;
        }

        // La fiecare request prelungim cu inca SessionMinutes.
        s.LastSeenAt = DateTime.UtcNow;
        s.ExpiresAt = DateTime.UtcNow.AddMinutes(SessionMinutes);
        await _db.SaveChangesAsync();
        WriteCookie(ctx, s.Id, s.ExpiresAt);

        return s;
    }

    private static string GenerateSessionId()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static void WriteCookie(HttpContext ctx, string sessionId, DateTime expires)
    {
        ctx.Response.Cookies.Append(CookieName, sessionId, new CookieOptions
        {
            HttpOnly = true,
            Secure = ctx.Request.IsHttps,
            SameSite = SameSiteMode.Strict,
            Path = "/",
            Expires = expires
        });
    }
}
