using Sonata.Security.Extensions;
using Sonata.Security.Permissions;
using System;
using System.Linq;
using Xunit;

namespace Sonata.Security.Tests.Permissions
{
	public class PermissionProviderTests
	{
		[Fact]
		public void PrologStructCanBeSerializedAsString()
		{
			var goal = PermissionProvider.BuildPredicate("authorisation", "argument1", "argument2", null);
			const string expected = "authorisation(argument1, argument2, _).";

			Assert.Equal(expected, goal);
		}

		public class PermissionProviderTestBench : IDisposable
		{
			protected readonly string FactsFilePath;
			protected readonly string RulesFilePath;
			protected readonly PermissionProvider Provider;

			public PermissionProviderTestBench()
			{
				FactsFilePath = System.IO.Path.GetTempFileName();
				RulesFilePath = System.IO.Path.GetTempFileName();
				Provider = new PermissionProvider(FactsFilePath, RulesFilePath);
			}

			private void ReleaseUnmanagedResources()
			{
				if (FactsFilePath != null)
				{
					System.IO.File.Delete(FactsFilePath);
				}
				if (RulesFilePath != null)
				{
					System.IO.File.Delete(RulesFilePath);
				}
			}

			public void Dispose()
			{
				ReleaseUnmanagedResources();
				GC.SuppressFinalize(this);
			}

			~PermissionProviderTestBench()
			{
				ReleaseUnmanagedResources();
			}
		}

		public class FactsTests : PermissionProviderTestBench
		{
			[Fact]
			public void AddFactAddsANewFactToTheFile()
			{
				Provider.Fetch();

				const string fact = "admin(xyz).";
				Provider.AddFact(fact);

				var lastFact = System.IO.File.ReadAllLines(FactsFilePath).LastOrDefault();
				Assert.Equal(fact, lastFact);
				Assert.True(Provider.Eval("admin", "xyz"));
			}

			[Fact]
			public void DuplicateAFactDoesNotChangeTheFile()
			{
				Provider.Fetch();

				const string fact = "admin(xyz).";
				Provider.AddFact(fact);
				Provider.AddFact(fact);

				var facts = System.IO.File.ReadAllLines(FactsFilePath);
				var duplicates = facts
					.GroupBy(f => f)
					.Where(factsGroup => factsGroup.Count() > 1)
					.Select(factsGroup => factsGroup.Key);

				Assert.Empty(duplicates);
				Assert.Contains(fact, facts);
				Assert.True(Provider.Eval("admin", "xyz"));
			}

			[Fact]
			public void RemoveFactRemovesTheFact()
			{
				var initialContent = new[] { "admin(abc).", "admin(def).", "admin(xyz)." };
				System.IO.File.WriteAllLines(FactsFilePath, initialContent);

				Provider.Fetch();

				var factToRemove = "admin(def).";

				Provider.RemoveFact(factToRemove);

				var facts = System.IO.File.ReadAllLines(FactsFilePath);

				Assert.Equal(2, facts.Length);
				Assert.DoesNotContain(factToRemove, facts);
				Assert.False(Provider.Eval("admin", "def"));
			}
		}

		public class RuntimeTests : PermissionProviderTestBench
		{
		    [Fact]
		    public void PrologEngineCanEvalPredicates()
		    {
		        Provider.Fetch();
		        var facts = new[] { "homme(socrate).", "droid(r2d2)." };
		        var rules = new[] { "mortel(Personne):-homme(Personne)." };

		        System.IO.File.WriteAllLines(FactsFilePath, facts);
		        System.IO.File.WriteAllLines(RulesFilePath, rules);

		        Provider.Fetch();

		        Assert.True(Provider.Eval("mortel", "socrate"));
		        Assert.False(Provider.Eval("mortel", "r2d2"));
		        Assert.True(Provider.Eval("mortel", "Inconnu"));
		    }


            [Fact]
			public void PrologEngineCanSolvePredicates()
			{
				var facts = new[] { "collab(afi).", "collab(lma)." };
				System.IO.File.WriteAllLines(FactsFilePath, facts);

				Provider.Fetch();
				
				var solutions = Provider.Solve("collab", "Collab").ToList();

				Assert.Equal(2, solutions.Count);
                Assert.True(solutions.All(s => s.ContainsKey("Collab")));
			    var collabs = solutions.Select(s => s["Collab"]).ToList();
                Assert.Contains("afi", collabs);
                Assert.Contains("lma", collabs);
			}
		}

		public class AuthorisationTests : PermissionProviderTestBench
		{
			[Fact]
			public void IsAuthorisedReturnsTrueIfRuleExistsInProlog()
			{
				var ruleset = new[] { $"{PermissionProvider.DefaultRuleName}(User,_,_,_):-isUser(User)." };
				System.IO.File.WriteAllLines(RulesFilePath, ruleset);

				var facts = new[] { "isUser(alice).", "isUser(bob)." };
				System.IO.File.WriteAllLines(FactsFilePath, facts);

				Provider.Fetch();

				var request = new PermissionRequest { User = "bob" };

				Assert.True(Provider.IsAuthorized(request));
			}
		}
	}
}
