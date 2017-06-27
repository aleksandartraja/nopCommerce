using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace Nop.Plugin.ExternalAuth.MailChimp.Components
{
    [ViewComponent(Name = "MailChimpAuthentication")]
    public class MailChimpAuthenticationViewComponent : ViewComponent
    {
        public async Task<IViewComponentResult> InvokeAsync()
        {
            return View("~/Plugins/ExternalAuth.MailChimp/Views/PublicInfo.cshtml");
        }
    }
}