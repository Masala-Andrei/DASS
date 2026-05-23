using AuthX.Vulnerable.Data;
using AuthX.Vulnerable.Models;

namespace AuthX.Vulnerable.Services;


// Userul poate edita cookie-ul din DevTools si poate accesa contul oricarui utilizator (acesta fiind doar
// un user id)
public static class SessionCookie
{
    public const string Name = "AUTHX_SESSION";

    public static void Set(HttpContext ctx, int userId)
    {
        ctx.Response.Cookies.Append(Name, userId.ToString(), new CookieOptions
        {
            // Cookie ul este facut fara httponly, secure si samesite, in plus expira si f greu
            HttpOnly = false,
            Secure = false,
            SameSite = SameSiteMode.Unspecified,
            Expires = DateTimeOffset.UtcNow.AddDays(30)
        });
    }

    public static void Clear(HttpContext ctx)
    {
        // Din nou, doar sterg cookie-ul de la client si nu e ok
        ctx.Response.Cookies.Delete(Name);
    }

    public static int? GetUserId(HttpContext ctx)
    {
        var raw = ctx.Request.Cookies[Name];
        if (string.IsNullOrEmpty(raw)) return null;
        return int.TryParse(raw, out var id) ? id : null;
    }
}

public class CurrentUserService
{
    private readonly AppDbContext _db;
    private readonly IHttpContextAccessor _http;
    private User? _cached;
    private bool _resolved;

    public CurrentUserService(AppDbContext db, IHttpContextAccessor http)
    {
        _db = db;
        _http = http;
    }

    public User? Get()
    {
        if (_resolved) return _cached;
        _resolved = true;

        var ctx = _http.HttpContext;
        if (ctx == null) return null;

        var id = SessionCookie.GetUserId(ctx);
        if (id == null) return null;

        _cached = _db.Users.FirstOrDefault(u => u.Id == id.Value);
        return _cached;
    }

    public bool IsAuthenticated => Get() != null;
}
