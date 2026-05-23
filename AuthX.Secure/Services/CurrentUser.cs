using AuthX.Secure.Models;

namespace AuthX.Secure.Services;

// Leg current user acum de sesiune astfel incat sa nu mai poata fi furata sesiunea in cazul in care un atacator face
// rost de cookie
public class CurrentUserService
{
    private readonly SessionService _sessions;
    private readonly IHttpContextAccessor _http;
    private User? _cached;
    private bool _resolved;

    public CurrentUserService(SessionService sessions, IHttpContextAccessor http)
    {
        _sessions = sessions;
        _http = http;
    }

    public async Task<User?> GetAsync()
    {
        if (_resolved) return _cached;
        _resolved = true;

        var ctx = _http.HttpContext;
        if (ctx == null) return null;

        var session = await _sessions.ResolveAsync(ctx);
        _cached = session?.User;
        return _cached;
    }

    public async Task<bool> IsAuthenticatedAsync() => (await GetAsync()) != null;
}
