using Microsoft.AspNetCore.Mvc;

namespace DotnetAuth.Controllers
{
    public class AuthController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
