using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using TwoFactorAuth.Data;
using TwoFactorAuth.Models;

namespace TwoFactorAuth.CustomTokenProviders
{
	public class CustomEmailTokenProvider<TUser> : TotpSecurityStampBasedTokenProvider<TUser> where TUser : class
	{
		private readonly ILogger<CustomEmailTokenProvider<TUser>> _logger;
		protected int _expireMinutes = 60;
		protected ApplicationDbContext _db;

		public CustomEmailTokenProvider(ILogger<CustomEmailTokenProvider<TUser>> logger, IConfiguration config, ApplicationDbContext db_context)
		{
			_logger = logger;
			var timeoutString = config.GetValue<string>("Authentication:EmailTwoFactorCodeExpireTimeMinutes");
			if (String.IsNullOrEmpty(timeoutString) && int.TryParse(timeoutString, out int minutes))
			{
				_expireMinutes = minutes;
			}
			_db = db_context;
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

			var dateTime = DateTime.UtcNow;
			var code = StubRfc6238AuthenticationService.GenerateCode(new SecurityToken(token), modifier).ToString("D6", CultureInfo.InvariantCulture);
			var identity = user as IdentityUser;
			var dbEntry = new EmailAuthToken
			{
				Code = GetHash(token, code),
				Userid = identity.Id,
				Created = dateTime
			};
			_db.EmailAuthTokens.Add(dbEntry);
			await _db.SaveChangesAsync();
			//var castedUser = user as IdentityUser;
			//var codeExpirationInfo = new
			//{
			//    userId = castedUser.Id,
			//    code = code,
			//    expireTime = DateTime.UtcNow.AddMinutes(60)
			//};
			return code;
		}

		public string GetHash(byte[] securityToken, string code)
		{
			using (var hashAlgorithm = new HMACSHA1(new SecurityToken(securityToken).GetDataNoClone()))
			{
				return Encoding.UTF8.GetString(hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(code)));
			}
		}

		/// </returns>
		public override async Task<bool> ValidateAsync(string purpose, string token, UserManager<TUser> manager, TUser user)
		{


			

			if (manager == null)
			{
				throw new ArgumentNullException(nameof(manager));
			}
			var identity = user as IdentityUser;
			var securityToken = await manager.CreateSecurityTokenAsync(user);
			var hash = GetHash(securityToken, token);
			var dbToken = _db.EmailAuthTokens.FirstOrDefault(x => x.Code == hash && x.Userid == identity.Id);
			if (dbToken != null)
			{
				var dbDate = DateTime.SpecifyKind(dbToken.Created, DateTimeKind.Utc);

				return ((DateTime.UtcNow - dbDate).Seconds < _expireMinutes * 60);
			}
			return false;
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
