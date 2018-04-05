#region Namespace Sonata.Security.Extensions
//	TODO
#endregion

using alice.tuprolog;
using System;

namespace Sonata.Security.Extensions
{
	public static class PermissionExtensions
	{
		public static Term AsTerm(this string value)
		{
			return Term.createTerm(String.IsNullOrEmpty(value) ? "_" : value);
		}
	}
}
