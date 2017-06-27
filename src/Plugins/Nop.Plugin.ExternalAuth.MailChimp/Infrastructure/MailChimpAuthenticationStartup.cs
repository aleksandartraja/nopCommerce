using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json.Linq;
using Nop.Core.Infrastructure;

namespace Nop.Plugin.ExternalAuth.MailChimp.Infrastructure
{
    /// <summary>
    /// Represents object for the configuring MailChimp authentication middleware on application startup
    /// </summary>
    public class MailChimpAuthenticationStartup : INopStartup
    {
        /// <summary>
        /// Add and configure any of the middleware
        /// </summary>
        /// <param name="services">Collection of service descriptors</param>
        /// <param name="configuration">Configuration root of the application</param>
        public void ConfigureServices(IServiceCollection services, IConfigurationRoot configuration)
        {
        }

        /// <summary>
        /// Configure the using of added middleware
        /// </summary>
        /// <param name="application">Builder for configuring an application's request pipeline</param>
        public void Configure(IApplicationBuilder application)
        {
            var settings = EngineContext.Current.Resolve<MailChimpAuthenticationSettings>();
            if (string.IsNullOrEmpty(settings?.ClientId) || string.IsNullOrEmpty(settings?.ClientSecret))
                return;

            //add the OAuth2 middleware
            application.UseOAuthAuthentication(new OAuthOptions
            {
                AuthenticationScheme = "MailChimp",

                //configure the OAuth2 Client ID and Client Secret
                ClientId = settings.ClientId,
                ClientSecret = settings.ClientSecret,

                //set the callback path, also ensure that you have added the URL as an Authorized Redirect URL in your MailChimp application
                CallbackPath = new PathString("/signin-mailchimp"),

                //configure the MailChimp endpoints                
                AuthorizationEndpoint = "https://login.mailchimp.com/oauth2/authorize",
                TokenEndpoint = "https://login.mailchimp.com/oauth2/token",
                UserInformationEndpoint = "https://login.mailchimp.com/oauth2/metadata",

                Events = new OAuthEvents
                {
                    // The OnCreatingTicket event is called after the user has been authenticated and the OAuth middleware has
                    // created an auth ticket. We need to manually call the UserInformationEndpoint to retrieve the user's information,
                    // parse the resulting JSON to extract the relevant information, and add the correct claims.
                    OnCreatingTicket = async context =>
                    {
                        //retrieve user info
                        var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
                        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);
                        request.Headers.Add("x-li-format", "json");

                        var response = await context.Backchannel.SendAsync(request, context.HttpContext.RequestAborted);
                        response.EnsureSuccessStatusCode();

                        //extract the user info object
                        var user = JObject.Parse(await response.Content.ReadAsStringAsync());
                        var nameIdentifier = user.Value<JObject>("login")?.Value<string>("login_id");
                        if (!string.IsNullOrEmpty(nameIdentifier))
                            context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, nameIdentifier));
                        var name = user.Value<JObject>("login")?.Value<string>("login_name");
                        if (!string.IsNullOrEmpty(name))
                            context.Identity.AddClaim(new Claim(ClaimTypes.Name, name));
                        var email = user.Value<JObject>("login")?.Value<string>("login_email");
                        if (!string.IsNullOrEmpty(email))
                            context.Identity.AddClaim(new Claim(ClaimTypes.Email, email));
                        var avatar = user.Value<JObject>("login")?.Value<string>("avatar");
                        if (!string.IsNullOrEmpty(avatar))
                            context.Identity.AddClaim(new Claim("avatar", avatar));
                        context.Ticket.Properties.StoreTokens(new[] { new AuthenticationToken { Name = "access_token", Value = context.AccessToken } });
                    }
                }
            });
        }

        /// <summary>
        /// Gets order of this startup configuration implementation
        /// </summary>
        public int Order
        {
            get { return 501; }
        }
    }
}
