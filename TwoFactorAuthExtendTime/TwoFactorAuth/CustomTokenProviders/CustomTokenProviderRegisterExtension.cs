using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace TwoFactorAuth.CustomTokenProviders
{
	public static class CustomTokenProviderRegisterExtension
	{
		public static IdentityBuilder AddPasswordlessLoginTotpTokenProvider(this IdentityBuilder builder)
		{
			var userType = builder.UserType;
			var totpProvider = typeof(CustomTotpTokenProvider<>).MakeGenericType(userType);
			//var totpProvider = typeof(StubTotpTokenProvider<>).MakeGenericType(userType);

			return builder.AddTokenProvider("CustomTotpTokenProvider", totpProvider);
		}
	}
}
