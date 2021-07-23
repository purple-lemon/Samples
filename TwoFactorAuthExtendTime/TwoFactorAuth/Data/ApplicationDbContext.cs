using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Text;
using TwoFactorAuth.Models;

namespace TwoFactorAuth.Data
{
	public class ApplicationDbContext : IdentityDbContext
	{
		public DbSet<EmailAuthToken> EmailAuthTokens { get; set; }
		public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
			: base(options)
		{
		}
	}
}
