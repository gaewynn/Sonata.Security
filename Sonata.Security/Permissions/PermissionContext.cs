#region Namespace Sonata.Security.Permission
//	TODO
# endregion

using System.Runtime.Serialization;
using Newtonsoft.Json;

namespace Sonata.Security.Permissions
{
	[JsonObject("permissionContext")]
	[DataContract(Name = "permissionContext")]
	public class PermissionContext
	{
		[JsonProperty("applicationKey")]
		[DataMember(Name = "applicationKey")]
		public string ApplicationKey { get; set; }

		[JsonProperty("userName")]
		[DataMember(Name = "userName")]
		public string UserName { get; set; }

		[JsonProperty("facts")]
		[DataMember(Name = "facts")]
		public string Facts { get; set; }

		[JsonProperty("rules")]
		[DataMember(Name = "rules")]
		public string Rules { get; set; }

		[JsonProperty("tokenLifeTime")]
		[DataMember(Name = "tokenLifeTime")]
		public int? TokenLifeTime { get; set; }

		[JsonIgnore]
		public PermissionProvider PermissionsProvider { get; set; }
	}
}
