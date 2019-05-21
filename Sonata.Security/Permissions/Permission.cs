#region Namespace Sonata.Security.Permission
//	TODO
# endregion

using System.Runtime.Serialization;

namespace Sonata.Security.Permissions
{
	/// <summary>
	/// Describes a set of security permissions applied to code. This class cannot be inherited.
	/// </summary>
	[DataContract(Name = "permission")]
	public class Permission
	{
		#region Properties

		[DataMember(Name = "entity")]
		public string Entity { get; set; }

		[DataMember(Name = "target")]
		public string Target { get; set; }

		[DataMember(Name = "accessTypes")]
		public AccessType.Values AccessTypes { get; set; }

		[DataMember(Name = "hasCreateAccess")]
		public bool HasCreateAccess => AccessTypes.HasFlag(AccessType.Values.Create);

		[DataMember(Name = "hasReadAccess")]
		public bool HasReadAccess => AccessTypes.HasFlag(AccessType.Values.Read);

		[DataMember(Name = "hasUpdateAccess")]
		public bool HasUpdateAccess => AccessTypes.HasFlag(AccessType.Values.Update);

		[DataMember(Name = "hasDeleteAccess")]
		public bool HasDeleteAccess => AccessTypes.HasFlag(AccessType.Values.Delete);

		#endregion
	}
}
