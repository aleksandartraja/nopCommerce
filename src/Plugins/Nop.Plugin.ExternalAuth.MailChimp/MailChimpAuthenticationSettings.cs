using Nop.Core.Configuration;

namespace Nop.Plugin.ExternalAuth.MailChimp
{
    /// <summary>
    /// Represents settings of the MailChimp authentication mehod
    /// </summary>
    public class MailChimpAuthenticationSettings : ISettings
    {
        /// <summary>
        /// Gets or sets OAuth2 client identifier
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        /// Gets or sets OAuth2 client secret
        /// </summary>
        public string ClientSecret { get; set; }
    }
}