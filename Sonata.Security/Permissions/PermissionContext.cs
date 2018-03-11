#region Namespace Sonata.Security.Permission
//	TODO
# endregion

using System.Runtime.Serialization;

namespace Sonata.Security.Permissions
{
	[DataContract(Name = "permissionContext")]
	public class PermissionContext
	{
		[DataMember(Name = "applicationKey")]
		public string ApplicationKey { get; set; }

		[DataMember(Name = "userName")]
		public string UserName { get; set; }

		[DataMember(Name = "facts")]
		public string Facts { get; set; }

		[DataMember(Name = "rules")]
		public string Rules { get; set; }

		[DataMember(Name = "tokenLifeTime")]
		public int? TokenLifeTime { get; set; }

		public PermissionProvider PermissionsProvider { get; set; }
	}
}
