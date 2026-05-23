using AuthX.Vulnerable.Services;
using Microsoft.AspNetCore.Mvc;

namespace AuthX.Vulnerable.Controllers;

public class HomeController : Controller
{
    private readonly CurrentUserService _current;

    public HomeController(CurrentUserService current)
    {
        _current = current;
    }

    public IActionResult Index()
    {
        ViewBag.Me = _current.Get();
        return View();
    }
}
