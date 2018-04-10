﻿#region Namespace Sonata.Security.Extensions
//	TODO
#endregion

using System;

namespace Sonata.Security.Extensions
{
	public static class PermissionExtensions
	{
		public static string AsTerm(this string value)
		{
			return String.IsNullOrEmpty(value)
				? "_"
				: value;
		}
	}
}