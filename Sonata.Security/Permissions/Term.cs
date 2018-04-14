using System.Diagnostics;
using System.Runtime.Serialization;

namespace Sonata.Security.Permissions
{
	[DebuggerDisplay("Type: {Type} / Name: {Name} / Value: {Value}")]
	[DataContract(Name = "term")]
	public class Term
	{
		[DataMember(Name = "type")]
		public string Type { get; set; }

		[DataMember(Name = "name")]
		public string Name { get; set; }

		[DataMember(Name = "value")]
		public string Value { get; set; }
	}
}
