#region Namespace Sonata.Security
//	The Sonata.Security namespace defines a principal object that represents the security context under which code is running.
#endregion

using System.Configuration;
using System.Linq;

namespace Sonata.Security
{
	internal class SecurityConfiguration
	{
		#region Constants

		private const string IsDebugModeEnabledKey = "Sonata.Internal.Debug";

		#endregion

		#region Properties

		public static bool IsDebugModeEnabled { get; set; }

		#endregion

		#region Constructors

		static SecurityConfiguration()
		{
			IsDebugModeEnabled = false;
			if (!ConfigurationManager.AppSettings.AllKeys.Contains(IsDebugModeEnabledKey))
				return;

			bool.TryParse(ConfigurationManager.AppSettings[IsDebugModeEnabledKey], out var isDebugModeEnabled);
			IsDebugModeEnabled = isDebugModeEnabled;
		}

		#endregion
	}
}
