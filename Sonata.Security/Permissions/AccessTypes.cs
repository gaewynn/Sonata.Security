#region Namespace Sonata.Security.Permission
//	TODO
#endregion

using System;
using Sonata.Core.Attributes;

namespace Sonata.Security.Permissions
{
	[Flags]
	public enum AccessTypes
	{
		None = 0,

		[StringValue("ajouter")]
		Create = 1,

		[StringValue("lecture")]
		Read = 2,

		[StringValue("modifier")]
		Update = 4,

		[StringValue("supprimer")]
		Delete = 8
	}
}
