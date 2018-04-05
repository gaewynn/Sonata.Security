#region Namespace Sonata.Security
//	The Sonata.Security namespace defines a principal object that represents the security context under which code is running.
#endregion

using Sonata.Security.Principal;
using System;
using System.Collections.Generic;

namespace Sonata.Security
{
	public class SecurityProvider
	{
		#region Constants

		/// <summary>
		/// A key allowing to know if the <see cref="IUserProvider"/> has been registered.
		/// The <see cref="IUserProvider"/> can only be registered once during the application startup.
		/// </summary>
		private const string UserProviderKey = "RegisterUserProvider";

		#endregion

		#region Members

		/// <summary>
		/// A list of providers already registered. This list tracks the providers registered to ensure they are only registered once.
		/// </summary>
		private static readonly List<string> ProvidersSet = new List<string>();

		#endregion

		#region Properties

		/// <summary>
		/// Gets the current <see cref="T:IUserProvider" /> presently registered in the Sonata.Security Library.
		/// </summary>
		/// <remarks>If no <see cref="T:IUserProvider" /> registration has been made yet, a default <see cref="T:WindowsWebUserProvider" /> will be returned.</remarks>
		public static IUserProvider UserProvider { get; private set; }

		#endregion

		#region Constructors

		private SecurityProvider()
		{
		}

		#endregion

		#region Methods

		/// <summary>
		/// Registers an <see cref="IUserProvider"/> and sets it as the current one used by the Sonata.Security Library.
		/// </summary>
		/// <param name="userProvider">An <see cref="IUserProvider"/> allowing to retrieve information about the current user. If null, a default <see cref="WindowsUserProvider"/> will be used as the <see cref="IUserProvider"/>.</param>
		/// <exception cref="InvalidOperationException">A call to the RegisterUserProvider method has already been done.</exception>
		public static void RegisterUserProvider(IUserProvider userProvider = null)
		{
			if (ProvidersSet.Contains(UserProviderKey))
				throw new InvalidOperationException("User provider already configured.");

			UserProvider = userProvider ?? WindowsUserProvider.Instance;
			ProvidersSet.Add(UserProviderKey);
		}

		internal static void Trace(string message)
		{
			if (!SecurityConfiguration.IsDebugModeEnabled
				|| String.IsNullOrWhiteSpace(message))
				return;

			Console.WriteLine($"{DateTime.Now:HH:mm:ss} - {message}");
		}
		
		#endregion
	}
}
