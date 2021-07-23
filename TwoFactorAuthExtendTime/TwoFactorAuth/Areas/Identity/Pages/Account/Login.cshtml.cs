using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.Threading;

namespace TwoFactorAuth.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class LoginModel : PageModel
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ILogger<LoginModel> _logger;

        public LoginModel(SignInManager<IdentityUser> signInManager, 
            ILogger<LoginModel> logger,
            UserManager<IdentityUser> userManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public IList<AuthenticationScheme> ExternalLogins { get; set; }

        public string ReturnUrl { get; set; }

        [TempData]
        public string ErrorMessage { get; set; }

        public class InputModel
        {
            [Required]
            [EmailAddress]
            public string Email { get; set; }

            [Required]
            [DataType(DataType.Password)]
            public string Password { get; set; }

            [Display(Name = "Remember me?")]
            public bool RememberMe { get; set; }
        }

        public async Task OnGetAsync(string returnUrl = null)
        {
            if (!string.IsNullOrEmpty(ErrorMessage))
            {
                ModelState.AddModelError(string.Empty, ErrorMessage);
            }

            returnUrl = returnUrl ?? Url.Content("~/");

            // Clear the existing external cookie to ensure a clean login process
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            ReturnUrl = returnUrl;
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");

            if (ModelState.IsValid)
            {
                // This doesn't count login failures towards account lockout
                // To enable password failures to trigger account lockout, set lockoutOnFailure: true
                var result = await _signInManager.PasswordSignInAsync(Input.Email, Input.Password, Input.RememberMe, lockoutOnFailure: false);
                if (result.Succeeded)
                {
                    _logger.LogInformation("User logged in.");
                    return LocalRedirect(returnUrl);
                }
                if (result.RequiresTwoFactor)
                {
                    var user = await _userManager.FindByEmailAsync(Input.Email);
                    var authenticatorCode = await _userManager.GenerateUserTokenAsync(user, "CustomTotpTokenProvider", "TwoFactor");
                    var isValid = await _userManager.VerifyTwoFactorTokenAsync(user, "CustomTotpTokenProvider", authenticatorCode);
                    string format = "mm:ss:fff";
                    var step = 100;
                    var s = Stopwatch.StartNew();
                    for (var i = 0; i < 20000; i = i + step)
                    {
                        isValid = await _userManager.VerifyTwoFactorTokenAsync(user, "CustomTotpTokenProvider", authenticatorCode);
                        
                        
						if (!isValid)
						{
                            _logger.LogInformation($"Not valid after time: {s.ElapsedMilliseconds} ms");
                            break;
                        } else
						{
                            _logger.LogInformation($"Token: {authenticatorCode}, time: {DateTime.Now.ToString(format)}. Is Valid: {isValid}");
                        }
                        Thread.Sleep(step);
                    }
                    //var isValid = await _signInManager.TwoFactorSignInAsync("CustomTotpTokenProvider", authenticatorCode, false, false);
                    //string format = "mm:ss";
                    //Debug.WriteLine($"Token: {token}, time: {DateTime.Now.ToString(format)}");
                    //Thread.Sleep(5000);

                    //Debug.WriteLine($"Token: {token}, time: {DateTime.Now.ToString(format)}. Is Valid: {isValid.Succeeded}");  
                    //Thread.Sleep(3000);
                    //isValid = await _signInManager.TwoFactorSignInAsync("CustomTotpTokenProvider", token, false, false);
                    //Debug.WriteLine($"Token: {token}, time: {DateTime.Now.ToString(format)}. Is Valid: {isValid.Succeeded}");
                    //Thread.Sleep(3000);
                    //isValid = await _signInManager.TwoFactorSignInAsync("CustomTotpTokenProvider", token, false, false);
                    //Debug.WriteLine($"Token: {token}, time: {DateTime.Now.ToString(format)}. Is Valid: {isValid.Succeeded}");
                    return RedirectToPage("./LoginWith2fa", new { ReturnUrl = returnUrl, RememberMe = Input.RememberMe });
                }
                if (result.IsLockedOut)
                {
                    _logger.LogWarning("User account locked out.");
                    return RedirectToPage("./Lockout");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    return Page();
                }
            }

            // If we got this far, something failed, redisplay form
            return Page();
        }
    }
}
