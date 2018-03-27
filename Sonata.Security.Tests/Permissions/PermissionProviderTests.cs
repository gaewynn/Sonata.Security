using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using alice.tuprolog;
using Sonata.Security.Permissions;
using Xunit;

namespace Sonata.Security.Tests.Permissions
{
    public class PermissionProviderTests
    {
        [Fact]
        public void PrologStructCanBeSerializedAsString()
        {
            var arguments = new[] { "argument1", "argument2", null }
                .Select(arg => arg.AsTerm())
                .ToArray();

            var goal = new Struct("authorisation", arguments);

            Assert.Equal("authorisation(argument1,argument2, _)", goal.toString());
        }

        public class PermissionProviderTestBench : IDisposable
        {
            protected readonly string _factsFilePath;
            protected readonly string _rulesFilePath;
            protected readonly PermissionProvider _provider;

            public PermissionProviderTestBench()
            {
                _factsFilePath = System.IO.Path.GetTempFileName();
                _rulesFilePath = System.IO.Path.GetTempFileName();
                _provider = new PermissionProvider(_factsFilePath, _rulesFilePath);
            }

            private void ReleaseUnmanagedResources()
            {
                if (_factsFilePath != null)
                {
                    System.IO.File.Delete(_factsFilePath);
                }
                if (_rulesFilePath != null)
                {
                    System.IO.File.Delete(_rulesFilePath);
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
                _provider.Fetch();

                const string fact = "admin(xyz).";
                _provider.AddFact(fact);

                var lastFact = System.IO.File.ReadAllLines(_factsFilePath).LastOrDefault();
                Assert.Equal(fact, lastFact);
                Assert.True(_provider.RunRule("admin", "xyz"));
            }

            [Fact]
            public void DuplicateAFactDoesNotChangeTheFile()
            {
                _provider.Fetch();

                const string fact = "admin(xyz).";
                _provider.AddFact(fact);
                _provider.AddFact(fact);

                var facts = System.IO.File.ReadAllLines(_factsFilePath);
                var duplicates = facts
                    .GroupBy(f => f)
                    .Where(factsGroup => factsGroup.Count() > 1)
                    .Select(factsGroup => factsGroup.Key);

                Assert.Empty(duplicates);
                Assert.Contains(fact, facts);
                Assert.True(_provider.RunRule("admin", "xyz"));
            }

            [Fact]
            public void RemoveFactRemovesTheFact()
            {
                var initialContent = new[] { "admin(abc).", "admin(def).", "admin(xyz)." };
                System.IO.File.WriteAllLines(_factsFilePath, initialContent);

                _provider.Fetch();

                var factToRemove = "admin(def).";

                _provider.RemoveFact(factToRemove);

                var facts = System.IO.File.ReadAllLines(_factsFilePath);

                Assert.Equal(2, facts.Length);
                Assert.DoesNotContain(factToRemove, facts);
                Assert.False(_provider.RunRule("admin", "def"));
            }
        }

        public class RuntimeTests : PermissionProviderTestBench
        {
            [Fact]
            public void PrologEngineIsCreatedAfterLoad()
            {
                _provider.Fetch();

                Assert.NotNull(_provider.PrologEngine);
            }

            [Fact]
            public void PrologFactsAreLoadedInitially()
            {
                var initialContent = new[] { "answerToLifeTheUniverseAndEverything(42)."};
                System.IO.File.WriteAllLines(_factsFilePath, initialContent);

                _provider.Fetch();

                Assert.True(_provider.RunRule("answerToLifeTheUniverseAndEverything", (string)null));
            }
        }

        public class AuthorisationTests : PermissionProviderTestBench
        {
            [Fact]
            public void IsAuthorisedReturnsTrueIfRuleExistsInProlog()
            {
                var ruleset = new[] { $"{PermissionProvider.DefaultRuleName}(User,_,_,_):-isUser(User)." };
                System.IO.File.WriteAllLines(_rulesFilePath, ruleset);

                var facts = new[] { "isUser(alice).", "isUser(bob)." };
                System.IO.File.WriteAllLines(_factsFilePath, facts);

                _provider.Fetch();

                var request = new PermissionRequest { User = "bob" };

                Assert.True(_provider.IsAuthorized(request));
            }
        }
    }
}
