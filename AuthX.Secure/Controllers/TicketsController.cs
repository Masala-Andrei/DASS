using AuthX.Secure.Data;
using AuthX.Secure.Models;
using AuthX.Secure.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthX.Secure.Controllers;

public class TicketsController : Controller
{
    private readonly AppDbContext _db;
    private readonly CurrentUserService _current;

    public TicketsController(AppDbContext db, CurrentUserService current)
    {
        _db = db;
        _current = current;
    }

    private async Task<User?> RequireUserAsync()
    {
        var u = await _current.GetAsync();
        return u;
    }

    public async Task<IActionResult> Index()
    {
        var me = await RequireUserAsync();
        if (me == null)
        {
            TempData["Info"] = "Trebuie sa fii logat.";
            return RedirectToAction("Login", "Auth");
        }

        var list = await _db.Tickets
            .Where(t => t.OwnerId == me.Id)
            .OrderByDescending(t => t.CreatedAt)
            .ToListAsync();

        ViewBag.Me = me;
        return View(list);
    }

    
    // Daca ticketul nu apartine userului curent, raspund cu 404, la fel ca pentru un ID
    // care nu exista. Asa nu confirm nici existenta lui
    public async Task<IActionResult> Details(int id)
    {
        var me = await RequireUserAsync();
        if (me == null)
        {
            TempData["Info"] = "Trebuie sa fii logat.";
            return RedirectToAction("Login", "Auth");
        }

        var t = await _db.Tickets
            .Include(x => x.Owner)
            .FirstOrDefaultAsync(x => x.Id == id && x.OwnerId == me.Id);

        if (t == null) return NotFound();

        ViewBag.Me = me;
        return View(t);
    }

    [HttpGet]
    public async Task<IActionResult> Create()
    {
        var me = await RequireUserAsync();
        if (me == null)
        {
            TempData["Info"] = "Trebuie sa fii logat.";
            return RedirectToAction("Login", "Auth");
        }
        return View(new TicketCreateViewModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create(TicketCreateViewModel vm)
    {
        var me = await RequireUserAsync();
        if (me == null)
        {
            TempData["Info"] = "Trebuie sa fii logat.";
            return RedirectToAction("Login", "Auth");
        }

        var allowedSeverities = new[] { "LOW", "MEDIUM", "HIGH" };
        var severity = allowedSeverities.Contains(vm.Severity?.ToUpperInvariant()) ? vm.Severity!.ToUpperInvariant() : "LOW";

        var ticket = new Ticket
        {
            Title = vm.Title?.Trim() ?? string.Empty,
            // Evit XSS ul pastrand doar textul brut, si lasand escape-ul sa se ocupe de restul
            Description = vm.Description ?? string.Empty,
            Severity = severity,
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
