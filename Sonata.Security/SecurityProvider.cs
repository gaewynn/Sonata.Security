#region Namespace Sonata.Security
//	The Sonata.Security namespace defines a principal object that represents the security context under which code is running.
#endregion

using System;
using Sonata.Diagnostics.Logs;
using Sonata.Security.Principal;

namespace Sonata.Security
{
	public class SecurityProvider
	{
		#region Properties

		public static WindowsUserProvider WindowsUserProvider => WindowsUserProvider.Instance;

		#endregion

		#region Constructors

		private SecurityProvider()
		{
		}

		#endregion

		#region Methods

		internal static void Trace(string message)
		{
			if (!SecurityConfiguration.IsDebugModeEnabled
				|| String.IsNullOrWhiteSpace(message))
				return;

			Console.WriteLine($"{DateTime.Now:HH:mm:ss} - {message}");
			TechnicalLog.Debug(typeof(SecurityProvider), message);
		}
		
		#endregion
	}
}
