using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using OtpNet;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TwoFactorAuth.CustomTokenProviders
{
	public class CustomTotpTokenProvider<TUser> : TotpSecurityStampBasedTokenProvider<TUser> where TUser : class
	{
        private CustomRfc6238AuthenticationService rfc6238AuthService;
        private readonly ILogger<CustomTotpTokenProvider<TUser>> _logger;
        private IConfiguration configuration;
        public CustomTotpTokenProvider(CustomRfc6238AuthenticationService rfcService, ILogger<CustomTotpTokenProvider<TUser>> logger, IConfiguration config) : base()
		{
            this.rfc6238AuthService = rfcService;
            _logger = logger;
            configuration = config;

        }
        public override Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<TUser> manager, TUser user)
		{
			return Task.FromResult(true);
		}

        public override async Task<string> GenerateAsync(string purpose, UserManager<TUser> manager, TUser user)
        {

            if (manager == null)
            {
                throw new ArgumentNullException(nameof(manager));
            }
            var token = await manager.CreateSecurityTokenAsync(user);
            var modifier = await GetUserModifierAsync(purpose, manager, user);

   //         var totp = new Totp(token, step: 60);
   //         //var cc = new Hotp(token).ComputeHOTP(1);
   //         //var step = 100;
   //         var code = totp.ComputeTotp();
			////for (var i = 0; i < 20000; i = i + step)
			////{
			////    _logger.LogInformation($"{code} Remain: {totp.RemainingSeconds()}");
			////}

			//return code;

			return  rfc6238AuthService.GenerateCode(new SecurityToken(token), modifier).ToString("D6", CultureInfo.InvariantCulture);
        }

        /// </returns>
        public override async Task<bool> ValidateAsync(string purpose, string token, UserManager<TUser> manager, TUser user)
        {
            if (manager == null)
            {
                throw new ArgumentNullException(nameof(manager));
            }
            int code;
            if (!int.TryParse(token, out code))
            {
                return false;
            }
            var securityToken = await manager.CreateSecurityTokenAsync(user);

			// TOTP
			var totp = new Totp(securityToken, step: 60);
			var result = totp.VerifyTotp(token, out long timeStepMatched);
			return result;

			var modifier = await GetUserModifierAsync(purpose, manager, user);
            return securityToken != null && rfc6238AuthService.ValidateCode(new SecurityToken(securityToken), code, modifier);
        }

        /// <summary>
        /// Returns a constant, provider and user unique modifier used for entropy in generated tokens from user information.
        /// </summary>
        /// <param name="purpose">The purpose the token will be generated for.</param>
        /// <param name="manager">The <see cref="UserManager{TUser}"/> that can be used to retrieve user properties.</param>
        /// <param name="user">The user a token should be generated for.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing a constant modifier for the specified 
        /// <paramref name="user"/> and <paramref name="purpose"/>.
        /// </returns>
        public override async Task<string> GetUserModifierAsync(string purpose, UserManager<TUser> manager, TUser user)
        {
            if (manager == null)
            {
                throw new ArgumentNullException(nameof(manager));
            }
            var userId = await manager.GetUserIdAsync(user);
            return "Totp:" + purpose + ":" + userId;
        }
    }
}
