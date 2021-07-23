using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace TwoFactorAuth.Models
{
	public class EmailAuthToken
	{
		public int Id { get; set; }
		public string Userid { get; set; }
		public string Code { get; set; }
		public DateTime Created { get; set; }
	}
}
