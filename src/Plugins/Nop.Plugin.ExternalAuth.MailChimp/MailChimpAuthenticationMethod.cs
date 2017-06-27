using Nop.Core;
using Nop.Core.Plugins;
using Nop.Services.Authentication.External;
using Nop.Services.Configuration;
using Nop.Services.Localization;

namespace Nop.Plugin.ExternalAuth.MailChimp
{
    public class MailChimpAuthenticationMethod : BasePlugin, IExternalAuthenticationMethod
    {
        #region Fields

        private readonly ISettingService _settingService;
        private readonly IWebHelper _webHelper;

        #endregion

        #region Ctor

        public MailChimpAuthenticationMethod(ISettingService settingService,
            IWebHelper webHelper)
        {
            this._settingService = settingService;
            this._webHelper = webHelper;
        }

        #endregion

        #region Methods

        /// <summary>
        /// Gets a configuration page URL
        /// </summary>
        public override string GetConfigurationPageUrl()
        {
            return $"{_webHelper.GetStoreLocation()}Admin/MailChimpAuthentication/Configure";
        }

        /// <summary>
        /// Gets a view component for displaying plugin in public store
        /// </summary>
        /// <param name="viewComponentName">View component name</param>
        /// <param name="viewComponentArguments">View component arguments</param>
        public void GetPublicViewComponent(out string viewComponentName, out object viewComponentArguments)
        {
            viewComponentName = "MailChimpAuthentication";
            viewComponentArguments = null;
        }

        /// <summary>
        /// Install plugin
        /// </summary>
        public override void Install()
        {
            //settings
            _settingService.SaveSetting(new MailChimpAuthenticationSettings());

            //locales
            this.AddOrUpdatePluginLocaleResource("Plugins.ExternalAuth.MailChimp.ClientId", "Client ID");
            this.AddOrUpdatePluginLocaleResource("Plugins.ExternalAuth.MailChimp.ClientId.Hint", "Enter the OAuth2 client ID here.");
            this.AddOrUpdatePluginLocaleResource("Plugins.ExternalAuth.MailChimp.ClientSecret", "Client secret");
            this.AddOrUpdatePluginLocaleResource("Plugins.ExternalAuth.MailChimp.ClientSecret.Hint", "Enter the OAuth2 client secret here.");

            base.Install();
        }

        public override void Uninstall()
        {
            //settings
            _settingService.DeleteSetting<MailChimpAuthenticationSettings>();

            //locales
            this.DeletePluginLocaleResource("Plugins.ExternalAuth.MailChimp.ClientId");
            this.DeletePluginLocaleResource("Plugins.ExternalAuth.MailChimp.ClientId.Hint");
            this.DeletePluginLocaleResource("Plugins.ExternalAuth.MailChimp.ClientSecret");
            this.DeletePluginLocaleResource("Plugins.ExternalAuth.MailChimp.ClientSecret.Hint");

            base.Uninstall();
        }

        #endregion
    }
}