#region Namespace Sonata.Security.Principal
//	The Sonata.Security.Principal namespace defines a principal object that represents the security context under which code is running.
#endregion

using System;
using System.Security.Principal;
using Sonata.Core.Extensions;

namespace Sonata.Security.Principal
{
	public class WindowsUserProvider : IUserProvider
	{
		#region Members

		private static WindowsUserProvider _windowsUserProvider;

		#endregion

		#region Properties

		public static WindowsUserProvider Instance { get { return _windowsUserProvider = _windowsUserProvider ?? new WindowsUserProvider(); } }

		#endregion

		#region Constructors

		private WindowsUserProvider()
		{
		}

		#endregion

		#region Methods

		#region IUserProvider Members

		/// <inheritdoc />
		/// <summary>
		/// Get a value indicating the current logged username.
		/// </summary>
		/// <param name="includeDomainIfAny">TRUE to include the domain; otherwise FALSE.</param>
		/// <returns>The current logged username.</returns>
		/// <remarks>
		/// The resulting username is based on the current HttpContext and need a Windows Authentication to work properly.
		/// </remarks>
		public virtual string GetCurrentUsername(bool includeDomainIfAny = true)
		{
			WindowsIdentity identity;
			try
			{
				identity = WindowsIdentity.GetCurrent();
			}
			catch (Exception ex)
			{
				//	TODO: log exception
				Console.WriteLine(ex.GetFullMessage());
				identity = null;
			}

			var userName = identity == null || String.IsNullOrWhiteSpace(identity.Name)
				? Environment.UserName
				: identity.Name;

			if (!String.IsNullOrWhiteSpace(userName) && !includeDomainIfAny)
				userName = userName.Split('\\').Length > 1 ? userName.Split('\\')[1] : userName;

			return userName;
		}

		#endregion

		#endregion
	}
}
