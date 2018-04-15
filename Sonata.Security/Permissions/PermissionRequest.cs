#region Namespace Sonata.Security.Permission
//	TODO
# endregion

using System.Runtime.Serialization;

namespace Sonata.Security.Permissions
{
	[DataContract(Name = "permissionRequest")]
	public sealed class PermissionRequest
	{
		[DataMember(Name = "user")]
		public string User { get; set; }

		[DataMember(Name = "target")]
		public string Target { get; set; }

		[DataMember(Name = "entity")]
		public string Entity { get; set; }

		[DataMember(Name = "action")]
		public string Action { get; set; }

		[DataMember(Name = "custom")]
		public object Custom { get; set; }
	}
}
