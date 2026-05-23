using AuthX.Vulnerable.Data;
using AuthX.Vulnerable.Models;
using AuthX.Vulnerable.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthX.Vulnerable.Controllers;

public class TicketsController : Controller
{
    private readonly AppDbContext _db;
    private readonly CurrentUserService _current;

    public TicketsController(AppDbContext db, CurrentUserService current)
    {
        _db = db;
        _current = current;
    }

    private IActionResult? RequireLogin()
    {
        if (!_current.IsAuthenticated)
        {
            TempData["Info"] = "Trebuie sa fii logat.";
            return RedirectToAction("Login", "Auth");
        }
        return null;
    }

    public async Task<IActionResult> Index()
    {
        if (RequireLogin() is { } redirect) return redirect;

        var me = _current.Get()!;
        var list = await _db.Tickets
            .Where(t => t.OwnerId == me.Id)
            .OrderByDescending(t => t.CreatedAt)
            .ToListAsync();

        ViewBag.Me = me;
        return View(list);
    }

    // Nu verific daca ticketul apartine userului curent, orice user logat poate accesa detaliile
    // oricarui ticket
    public async Task<IActionResult> Details(int id)
    {
        if (RequireLogin() is { } redirect) return redirect;

        var t = await _db.Tickets.Include(x => x.Owner).FirstOrDefaultAsync(x => x.Id == id);
        if (t == null) return NotFound();

        ViewBag.Me = _current.Get();
        return View(t);
    }

    [HttpGet]
    public IActionResult Create()
    {
        if (RequireLogin() is { } redirect) return redirect;
        return View(new TicketCreateViewModel());
    }

    [HttpPost]
    public async Task<IActionResult> Create(TicketCreateViewModel vm)
    {
        if (RequireLogin() is { } redirect) return redirect;

        var me = _current.Get()!;
        var ticket = new Ticket
        {
            Title = vm.Title,
            // Descrierea e afisata ca raw ceea ce poate duce la un XSS attack
            Description = vm.Description,
            Severity = string.IsNullOrWhiteSpace(vm.Severity) ? "LOW" : vm.Severity,
            Status = "OPEN",
            OwnerId = me.Id,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };
        _db.Tickets.Add(ticket);
        await _db.SaveChangesAsync();

        return RedirectToAction(nameof(Index));
    }
}
