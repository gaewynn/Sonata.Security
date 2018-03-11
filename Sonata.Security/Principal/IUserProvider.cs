#region Namespace Sonata.Security.Principal
//	The Sonata.Security.Principal namespace defines a principal object that represents the security context under which code is running.
#endregion

namespace Sonata.Security.Principal
{
	/// <summary>
	/// An interface providing functionnalities about the current logged user.
	/// </summary>
	public interface IUserProvider
	{
		/// <summary>
		/// Get a value indicating the current logged username.
		/// </summary>
		/// <param name="includeDomainIfAny">TRUE to include the domain; otherwise FALSE.</param>
		/// <returns>The current logged username.</returns>
		string GetCurrentUsername(bool includeDomainIfAny = true);
	}
}