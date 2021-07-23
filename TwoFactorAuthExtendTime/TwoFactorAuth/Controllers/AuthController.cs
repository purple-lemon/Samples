using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using TwoFactorAuth.Models;

namespace TwoFactorAuth.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	public class AuthController : ControllerBase
	{
		private readonly UserManager<IdentityUser> _userManager;
		private readonly SignInManager<IdentityUser> _signInManager;

		public AuthController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager)
		{
			_userManager = userManager;
			_signInManager = signInManager;
		}
		[HttpPost]
		public async Task<string> Code(UserModel model)
		{
			var user = await _userManager.FindByEmailAsync(model.Name);
			var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

			var signInResult = await _signInManager.TwoFactorSignInAsync("Email", token, false, false);
			return token;

		}
	}
}
