#region Namespace Sonata.Security.Permission
//	TODO
#endregion

using System;
using Sonata.Core.Attributes;

namespace Sonata.Security.Permissions
{
    public class AccessType
    {
        public const string Create = "ajouter";
        public const string Read = "lecture";
        public const string Update = "modifier";
        public const string Delete = "supprimer";

        [Flags]
        public enum Values
        {
            None = 0,

            [StringValue(AccessType.Create)]
            Create = 1,

            [StringValue(AccessType.Read)]
            Read = 2,

            [StringValue(AccessType.Update)]
            Update = 4,

            [StringValue(AccessType.Delete)]
            Delete = 8
        }
    }
}
