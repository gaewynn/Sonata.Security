using System;
using System.Linq;
using Sonata.Security.Permissions;
using Sonata.Security.Tests.Permissions.Fixtures;
using Xunit;

namespace Sonata.Security.Tests.Permissions
{
	[CollectionDefinition("PermissionProvider_Collection")]
	public class PermissionProviderCollection : ICollectionFixture<PermissionProviderFixture>
	{
		// This class has no code, and is never created. Its purpose is simply
		// to be the place to apply [CollectionDefinition] and all the
		// ICollectionFixture<> interfaces.
	}

	[CollectionDefinition("PermissionProvider_ManagePredicates_Collection")]
	public class PermissionProviderManagePredicatesCollection : ICollectionFixture<PermissionProviderFixture>
	{
		// This class has no code, and is never created. Its purpose is simply
		// to be the place to apply [CollectionDefinition] and all the
		// ICollectionFixture<> interfaces.
	}

	[Collection("PermissionProvider_Collection")]
	public class PermissionProviderTests
	{
		#region Members

		protected readonly PermissionProviderFixture Fixture;

		#endregion

		#region Constructors

		public PermissionProviderTests(PermissionProviderFixture fixture)
		{
			Fixture = fixture;
		}

		#endregion

		public class BuildPredicateTests : PermissionProviderTests
		{
			#region Constructors

			public BuildPredicateTests(PermissionProviderFixture fixture)
				: base(fixture)
			{ }

			#endregion

			#region Methods

			[Fact]
			public void PrologStructCanBeSerializedAsString()
			{
				var goal = PermissionProvider.BuildPredicate("authorisation", "argument1", "argument2", null);
				const string expected = "authorisation(argument1, argument2, _).";

				Assert.Equal(expected, goal);
			}

			#endregion
		}
		
		public class EvalTests : PermissionProviderTests
		{
			#region Constructors

			public EvalTests(PermissionProviderFixture fixture)
				: base(fixture)
			{ }

			#endregion

			#region Methods

			[Fact]
			public void PrologEngineCanEvalPredicates()
			{
				Assert.True(Fixture.Provider.Eval("mortel", "socrate"));
				Assert.False(Fixture.Provider.Eval("mortel", "r2d2"));
				Assert.True(Fixture.Provider.Eval("mortel", "Inconnu"));
			}

			#endregion
		}

		public class SolveTests : PermissionProviderTests
		{
			#region Constructors

			public SolveTests(PermissionProviderFixture fixture)
				: base(fixture)
			{ }

			#endregion

			#region Methods

			[Fact]
			public void PrologEngineCanSolveUnaryPredicates()
			{
				var solutions = Fixture.Provider.Solve("collab", "Collab").ToList();

				Assert.Equal(2, solutions.Count);
				Assert.True(solutions.All(s => s.ContainsTerm("Collab")));
				var collabs = solutions.Select(s => s.GetTermValue("Collab")).ToList();
				Assert.Contains("afi", collabs);
				Assert.Contains("lma", collabs);
			}

			[Fact]
			public void PrologEngineCanSolveBinaryPredicates()
			{
				var solutions = Fixture.Provider.Solve("collab", "Collab", "'ge'").ToList();

				Assert.Equal(2, solutions.Count);
				Assert.True(solutions.All(s => s.ContainsTerm("Collab")));
				var collabs = solutions.Select(s => s.GetTermValue("Collab")).ToList();
				Assert.Contains("afi", collabs);
				Assert.Contains("lma", collabs);
			}

			[Fact]
			public void PrologEngineCanSolveUnboundPredicatesWithWildcards()
			{
				var solutions = Fixture.Provider.Solve("responsableActivite", "afi", "Activite").ToList();

				Assert.Equal(2, solutions.Count);
				Assert.True(solutions.All(s => s.ContainsTerm("Activite")));
				var activites = solutions.Select(s => s.GetTermValue("Activite")).ToList();
				Assert.Contains("\".A1\"", activites);
				Assert.Contains("2", activites);
			}

			#endregion
		}

		public class IsAuthorizedTests : PermissionProviderTests
		{
			#region Constructors

			public IsAuthorizedTests(PermissionProviderFixture fixture)
				: base(fixture)
			{ }

			#endregion

			#region Methods

			[Fact]
			public void IsAuthorisedReturnsTrueIfRuleExistsInProlog()
			{
				var request = new PermissionRequest { User = "bob" };

				Assert.True(Fixture.Provider.IsAuthorized(request));
			}

			[Fact]
			public void IsAuthorisedReturnsTrueIfRuleExistsInPrologFile()
			{
				var request = new PermissionRequest
				{
					User = "afi",
					Action = "lecture",
					Entity = "collaborateur"
				};

				Assert.True(Fixture.SampleProvider.IsAuthorized(request));
			}

			#endregion
		}

		public class GetAuthorizedTargetsTests : PermissionProviderTests
		{
			#region Constructors

			public GetAuthorizedTargetsTests(PermissionProviderFixture fixture)
				: base(fixture)
			{ }

			#endregion

			#region Methods

			[Fact]
			public void GetAuthorizedTargetReturnsAllTargetsMatchingTheRequest()
			{
				var request = new PermissionRequest { User = "alice", Action = "lecture", Entity = "stuff" };

				var targets = Fixture.Provider.GetAuthorizedTargets(request)?.Distinct().ToList();

				Assert.NotNull(targets);
				Assert.Equal(2, targets.Count);
				Assert.Contains("publicStuff", targets);
				Assert.Contains("restrictedStuff", targets);
			}

			#endregion
		}

		public class GetTargetPermissionsTests : PermissionProviderTests
		{
			#region Constructors

			public GetTargetPermissionsTests(PermissionProviderFixture fixture)
				: base(fixture)
			{ }

			#endregion

			#region Methods

			[Fact]
			public void GetTargetPermissionsReturnsThePermissionsForTheUserAndEntity()
			{
				var request = new PermissionRequest { User = "alice", Entity = "stuff" };

				var permission = Fixture.Provider.GetTargetPermissions(request);

				Assert.Equal("stuff", permission.Entity);
				Assert.Null(permission.Target);
				Assert.Equal(AccessTypes.Read | AccessTypes.Update, permission.AccessTypes);
			}
			
			#endregion
		}

		public class GetUserPermissionsTests : PermissionProviderTests
		{
			#region Constructors

			public GetUserPermissionsTests(PermissionProviderFixture fixture)
				: base(fixture)
			{ }

			#endregion

			#region Methods

			[Fact]
			public void GetUserPermissions()
			{
				var userPermissions = Fixture.Provider.GetUserPermissions(new PermissionRequest { User = "afi" }).ToList();
				Assert.NotNull(userPermissions);
				Assert.Single(userPermissions);
				Assert.Equal("collaborateur", userPermissions.ElementAt(0).Entity);
				Assert.True(userPermissions.ElementAt(0).HasCreateAccess);
				Assert.True(userPermissions.ElementAt(0).HasReadAccess);
				Assert.True(userPermissions.ElementAt(0).HasUpdateAccess);
				Assert.True(userPermissions.ElementAt(0).HasDeleteAccess);
			}

			#endregion
		}
	}

	[Collection("PermissionProvider_ManagePredicates_Collection")]
	public class PermissionProviderManagePredicatesTests
	{
		#region Members

		protected readonly PermissionProviderFixture Fixture;

		#endregion

		#region Constructors

		public PermissionProviderManagePredicatesTests(PermissionProviderFixture fixture)
		{
			Fixture = fixture;
		}

		#endregion

		public class ManagePredicatesTests : PermissionProviderTests
		{
			#region Constructors

			public ManagePredicatesTests(PermissionProviderFixture fixture)
				: base(fixture)
			{ }

			#endregion

			#region Methods

			[Fact]
			public void AddFactAddsANewFactToTheFile()
			{
				const string fact = "admin(xyz).";
				Fixture.Provider.AddFact(fact);

				var lastFact = System.IO.File.ReadAllLines(Fixture.FactsFilePath).LastOrDefault();
				Assert.Equal(fact, lastFact);
				Assert.True(Fixture.Provider.Eval("admin", "xyz"));
			}

			[Fact]
			public void DuplicateAFactDoesNotChangeTheFile()
			{
				const string fact = "admin(xyz).";
				Fixture.Provider.AddFact(fact);
				Fixture.Provider.AddFact(fact);

				var facts = System.IO.File.ReadAllLines(Fixture.FactsFilePath);
				var duplicates = facts
					.GroupBy(f => f)
					.Where(factsGroup => factsGroup.Count() > 1)
					.Select(factsGroup => factsGroup.Key);

				Assert.Empty(duplicates);
				Assert.Contains(fact, facts);
				Assert.True(Fixture.Provider.Eval("admin", "xyz"));
			}

			[Fact]
			public void RemoveFactRemovesTheFact()
			{
				var initialContent = new[] { "admin(abc).", "admin(def).", "admin(xyz)." };
				System.IO.File.WriteAllLines(Fixture.FactsFilePath, initialContent);

				const string factToRemove = "admin(def).";

				Fixture.Provider.RemoveFact(factToRemove);

				var facts = System.IO.File.ReadAllLines(Fixture.FactsFilePath);

				Assert.Equal(2, facts.Length);
				Assert.DoesNotContain(factToRemove, facts);
				Assert.False(Fixture.Provider.Eval("admin", "def"));
			}

			[Fact]
			public void AddFactsInADiscontiguousWay()
			{
				Assert.Throws<Exception>(() =>
				{
					Fixture.Provider.AddFact("planet(earth).");
					Fixture.Provider.AddFact("constellation(Andromeda).");
					Fixture.Provider.AddFact("planet(mars).");
				});
			}

			#endregion
		}
	}
}
