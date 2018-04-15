#region Namespace Sonata.Security.Permission
//	TODO
#endregion

using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;

namespace Sonata.Security.Permissions
{
	[DataContract(Name = "solution")]
	public class Solution : List<Term>
	{
		#region Constructors

		public Solution(IEnumerable<Term> terms)
			: base(terms)
		{ }

		#endregion

		#region Methods

		public string GetTermValue(string name)
		{
			return ContainsTerm(name)
				? this.Single(e => e.Name == name).Value
				: null;
		}

		public string GetTypeValue(string name)
		{
			return ContainsTerm(name)
				? this.Single(e => e.Name == name).Type
				: null;
		}

		public bool ContainsTerm(string name)
		{
			return this.Any(e => e.Name == name);
		}

		#endregion
	}
}
