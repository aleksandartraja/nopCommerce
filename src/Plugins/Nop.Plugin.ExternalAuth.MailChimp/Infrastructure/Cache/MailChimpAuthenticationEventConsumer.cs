using System.Linq;
using System.Security.Claims;
using Nop.Core.Domain.Customers;
using Nop.Services.Authentication.External;
using Nop.Services.Common;
using Nop.Services.Events;

namespace Nop.Admin.Infrastructure.Cache
{
    /// <summary>
    /// MailChimp authentication event consumer (used for saving customer fields on registration)
    /// </summary>
    public partial class MailChimpAuthenticationEventConsumer : IConsumer<CustomerAutoRegisteredByExternalMethodEvent>
    {
        #region Constants

        private const string PROVIDER_SYSTEM_NAME = "ExternalAuth.MailChimp";

        #endregion

        #region Fields

        private readonly IGenericAttributeService _genericAttributeService;

        #endregion

        #region Ctor

        public MailChimpAuthenticationEventConsumer(IGenericAttributeService genericAttributeService)
        {
            this._genericAttributeService = genericAttributeService;
        }

        #endregion

        #region Methods

        public void HandleEvent(CustomerAutoRegisteredByExternalMethodEvent eventMessage)
        {
            if (eventMessage?.Customer == null || eventMessage?.AuthenticationParameters == null)
                return;

            //handle event only for this authentication method
            if (!eventMessage.AuthenticationParameters.ProviderSystemName.Equals(PROVIDER_SYSTEM_NAME))
                return;

            //store some of the customer fields
            var firstName = eventMessage.AuthenticationParameters.Claims?.FirstOrDefault(claim => claim.Type == ClaimTypes.Name)?.Value;
            if (!string.IsNullOrEmpty(firstName))
                _genericAttributeService.SaveAttribute(eventMessage.Customer, SystemCustomerAttributeNames.FirstName, firstName);

            //TODO uploading avatar
        }

        #endregion
    }
}