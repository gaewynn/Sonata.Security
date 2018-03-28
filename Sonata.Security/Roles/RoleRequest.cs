#region Namespace Sonata.Security.Permission
//	TODO
# endregion

using System.Runtime.Serialization;

namespace Sonata.Security.Roles
{
    [DataContract(Name = "roleRequest")]
    public sealed class RoleRequest
    {
        [DataMember(Name = "applicationToken")]
        public string ApplicationToken { get; set; }

        [DataMember(Name = "fact")]
        public string Fact { get; set; }
    }
}
