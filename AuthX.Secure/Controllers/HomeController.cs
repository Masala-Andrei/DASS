using AuthX.Secure.Services;
using Microsoft.AspNetCore.Mvc;

namespace AuthX.Secure.Controllers;

public class HomeController : Controller
{
    private readonly CurrentUserService _current;

    public HomeController(CurrentUserService current)
    {
        _current = current;
    }

    public async Task<IActionResult> Index()
    {
        ViewBag.Me = await _current.GetAsync();
        return View();
    }
}
