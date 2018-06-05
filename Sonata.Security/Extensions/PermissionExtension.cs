#region Namespace Sonata.Security.Extensions
//	TODO
#endregion

using System;
using Sonata.Core.Extensions;

namespace Sonata.Security.Extensions
{
	public static class PermissionExtensions
	{
		public static string AsPrologConstant(this string value)
		{
			if (value == "_")
				return value;

			return String.IsNullOrEmpty(value)
				? "_"
				: $"{value.DoubleQuote()}";
		}
	}
}
