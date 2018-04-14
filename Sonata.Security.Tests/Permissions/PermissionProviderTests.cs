using Sonata.Security.Permissions;
using System;
using System.Linq;
using Xunit;

namespace Sonata.Security.Tests.Permissions
{
	public class PermissionProviderTests
	{
		public PermissionProviderTests()
		{
			SecurityProvider.Configure(true);
		}

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
				const string fact = "admin(xyz).";
				Provider.AddFact(fact);

				var lastFact = System.IO.File.ReadAllLines(FactsFilePath).LastOrDefault();
				Assert.Equal(fact, lastFact);
				Assert.True(Provider.Eval("admin", "xyz"));
			}

			[Fact]
			public void DuplicateAFactDoesNotChangeTheFile()
			{
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
				
				const string factToRemove = "admin(def).";

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
				Provider.AddFacts(new[] { "homme(socrate).", "droid(r2d2)." });
				Provider.AddRules(new[] { "mortel(Personne):-homme(Personne)." });
				
				Assert.True(Provider.Eval("mortel", "socrate"));
				Assert.False(Provider.Eval("mortel", "r2d2"));
				Assert.True(Provider.Eval("mortel", "Inconnu"));
			}

			[Fact]
			public void PrologEngineCanSolveUnaryPredicates()
			{
				Provider.AddFacts(new[] { "collab('afi').", "collab(lma)." });
				
				var solutions = Provider.Solve("collab", "Collab").ToList();

				Assert.Equal(2, solutions.Count);
				Assert.True(solutions.All(s => s.ContainsTerm("Collab")));
				var collabs = solutions.Select(s => s.GetTermValue("Collab")).ToList();
				Assert.Contains("afi", collabs);
				Assert.Contains("lma", collabs);
			}

			[Fact]
			public void PrologEngineCanSolveBinaryPredicates()
			{
				var facts = new[] {
					"collab(afi, ge).",
					"collab(lma, ge).",
					"collab(obl, ls)."
				};
				System.IO.File.WriteAllLines(FactsFilePath, facts);

				Provider.AddFacts(facts);

				var solutions = Provider.Solve("collab", "Collab", "'ge'").ToList();

				Assert.Equal(2, solutions.Count);
				Assert.True(solutions.All(s => s.ContainsTerm("Collab")));
				var collabs = solutions.Select(s => s.GetTermValue("Collab")).ToList();
				Assert.Contains("afi", collabs);
				Assert.Contains("lma", collabs);
			}

			[Fact]
			public void PrologEngineCanSolveUnboundPredicatesWithWildcards()
			{
				var facts = new[] {
					"responsableActivite(afi, \".A1\").",
					"responsableActivite(afi, _).",
				};
				
				Provider.AddFacts(facts);

				var solutions = Provider.Solve("responsableActivite", "afi", "Activite").ToList();

				Assert.Single(solutions);
				Assert.True(solutions.All(s => s.ContainsTerm("Activite")));
				var activites = solutions.Select(s => s.GetTermValue("Activite")).ToList();
				Assert.Equal("\".A1\"", activites[0]);
			}
		}

		// TODO Add a test for wildcard variables in the rules (_).
		// In this case, the variables are not bound to any value in the solution
		// So the variables dictionary has no key for this variable
		// One way to handle this would be to pass the list of variables to Solve or parsing the query to extract variables,
		// and preload the dictionary with noll values for each variable.
		public class AuthorizationManagerTestBench : PermissionProviderTestBench
		{
			private static readonly string[] Facts = {
				"powerUser(alice).",
				"powerUser(bob).",
				"administrator(bob).",
				"chuckNorris(chuck).",
			};

			private static readonly string[] Rules =
			{
				"authorisation(User, Target, stuff, Action):-userCanDoActionOnTarget(User, Action, Target).",
				"is_user(User):-is_powerUser(User).",
				"is_powerUser(User):-powerUser(User).",
				"is_powerUser(User):-is_administrator(User).",
				"is_administrator(User):-administrator(User).",
				"is_administrator(User):-is_chuckNorris(User).",
				"is_chuckNorris(User):-chuckNorris(User).",
				"userCanDoActionOnTarget(User, lecture, publicStuff):-is_user(User).",
				"userCanDoActionOnTarget(User, modifier, publicStuff):-is_powerUser(User).",
				"userCanDoActionOnTarget(User, lecture, restrictedStuff):-is_powerUser(User).",
				"userCanDoActionOnTarget(User, modifier, restrictedStuff):-is_administrator(User).",
				"userCanDoActionOnTarget(User, lecture, adminStuff):-is_administrator(User).",
				"userCanDoActionOnTarget(User, _, _):-is_chuckNorris(User).",
			};

			public AuthorizationManagerTestBench()
			{
				System.IO.File.WriteAllLines(FactsFilePath, Facts);
				System.IO.File.WriteAllLines(RulesFilePath, Rules);
				Provider.AddFacts(Facts);
				Provider.AddRules(Rules);
			}
		}

		public class IsAuthorizedTests : AuthorizationManagerTestBench
		{
			[Fact]
			public void IsAuthorisedReturnsTrueIfRuleExistsInProlog()
			{
				var request = new PermissionRequest { User = "bob" };

				Assert.True(Provider.IsAuthorized(request));
			}
		}

		public class GetAuthorizedTargetsTests : AuthorizationManagerTestBench
		{
			[Fact]
			public void GetAuthorizedTargetReturnsAllTargetsMatchingTheRequest()
			{
				var request = new PermissionRequest { User = "alice", Action = "lecture", Entity = "stuff" };

				var targets = Provider.GetAuthorizedTargets(request);

				Assert.Equal(2, targets.Count());
				Assert.Contains("publicStuff", targets);
				Assert.Contains("restrictedStuff", targets);
			}
		}

		public class GetTargetPermissionsTests : AuthorizationManagerTestBench
		{
			[Fact]
			public void GetTargetPermissionsReturnsThePermissionsForTheUserAndEntity()
			{
				var request = new PermissionRequest { User = "alice", Entity = "stuff" };

				var permission = Provider.GetTargetPermissions(request);

				Assert.Equal("stuff", permission.Entity);
				Assert.Null(permission.Target);
				Assert.Equal(AccessTypes.Read | AccessTypes.Update, permission.AccessTypes);
			}
		}
	}
}
