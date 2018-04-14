#region Namespace Sonata.Security.Permission
//	TODO
#endregion

using Sonata.Core.Extensions;
using Sonata.Security.Extensions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using Prolog;

namespace Sonata.Security.Permissions
{
    public class PermissionProvider
    {
        #region Constants

        public const string DefaultRuleName = "authorisation";
        public const string ActionLecture = "lecture";
        public const string ActionAjouter = "ajouter";
        public const string ActionModifier = "modifier";
        public const string ActionSupprimer = "supprimer";

        #endregion

        #region Members

        protected string Entity;
        protected string PermissionCheck;
        protected readonly List<string> Actions = new List<string> { ActionLecture, ActionAjouter, ActionModifier, ActionSupprimer };
        private readonly string _factsFileFullName;
        private readonly string _rulesFileFullName;

        #endregion

        #region Properties

        private PrologEngine PrologEngine { get; set; }

        #endregion

        #region Constructors

        public PermissionProvider(string factsFileFullName, string rulesFileFullName)
        {
            _factsFileFullName = factsFileFullName;
            _rulesFileFullName = rulesFileFullName;

            SecurityProvider.Trace($"Facts file: {_factsFileFullName}");
            SecurityProvider.Trace($"Rules file: {_rulesFileFullName}");
        }

        #endregion

        #region Methods

        /// <summary>
        /// Evaluate a predicate. The predicate can contain Prolog variables.
        /// </summary>
        /// <param name="ruleName"></param>
        /// <param name="arguments"></param>
        /// <returns></returns>
        public virtual bool Eval(string ruleName = DefaultRuleName, params string[] arguments)
        {
            SecurityProvider.Trace($"Call to {nameof(Eval)}");
            try
            {
                var goal = BuildPredicate(ruleName, arguments);
                if (SecurityConfiguration.IsDebugModeEnabled)
                    SecurityProvider.Trace($"   Running predicate: {goal}");

                var result = PrologEngine.GetFirstSolution(goal);
                return result.Solved;
            }
            catch (Exception ex)
            {
                SecurityProvider.Trace($"   Error: {ex.GetFullMessage()}");
                throw;
            }
        }

        /// <summary>
        /// Evaluate a partially bound predicate (with Prolog variables) and returns the solutions as a collection of dictionaries.
        /// Each dictionary is the set of matching variables, with their bound values.
        /// If the predicate is fully bound, then the return value is a collection of empty dictionaries.
        /// </summary>
        /// <param name="ruleName"></param>
        /// <param name="arguments"></param>
        /// <returns></returns>
        public virtual IEnumerable<Dictionary<string, string>> Solve(string ruleName = DefaultRuleName, params string[] arguments)
        {
            SecurityProvider.Trace($"Call to {nameof(Solve)}");
            try
            {
                var goal = BuildPredicate(ruleName, arguments);
                if (SecurityConfiguration.IsDebugModeEnabled)
                {
                    SecurityProvider.Trace($"   Running predicate: {goal}");
                }

	            var variableNames = arguments.Where(arg => Regex.IsMatch(arg ?? "", "^[A-Z]")).ToList();

				// CsProlog is half-assed, and GetAllSolutions does not work.
				// We reuse the implementation of GetFirstSolution instead.
	            PrologEngine.Query = goal;
                var prologSolutions = PrologEngine.SolutionIterator;

				// Warning, the solution iterator returns one more result after exploring the whole tree of solutions.
				// Fortunately, this solution has the Solved flag set to true
	            var solutions = prologSolutions
		            .Where(solution => solution.Solved)
			        .Select(solution => solution.VarValuesIterator
						.Where(v => ((PrologEngine.BaseTerm)v.Value).IsAtomic) // This is required to exclude wildcards from the solution set.
			            .ToDictionary(v => v.Name.ToString(), v => v.Value.ToString()))
			        .Distinct()
		            .ToList();

	            foreach (var s in solutions)
	            {
		            foreach (var name in variableNames)
		            {
			            if (!s.ContainsKey(name))
				            s[name] = null;
		            }
	            }

	            return solutions;
            }
            catch (Exception ex)
            {
                SecurityProvider.Trace($"   Error: {ex.GetFullMessage()}");
                throw;
            }
        }

        public virtual void AddFact(string fact)
        {
            SecurityProvider.Trace($"Call to {nameof(AddFact)}");

            if (SecurityConfiguration.IsDebugModeEnabled)
            {
                SecurityProvider.Trace($"   Adding fact: {fact}");
            }

            var facts = System.IO.File.ReadAllLines(_factsFileFullName);

            if (facts.Contains(fact))
            {
                SecurityProvider.Trace("   Fact already exists: nothing to do.");
                return;
            }

            SecurityProvider.Trace("   Appending fact...");
            System.IO.File.WriteAllLines(_factsFileFullName, facts.Append(fact));
            LoadEngine();
        }

        public virtual void RemoveFact(string fact)
        {
            SecurityProvider.Trace($"Call to {nameof(RemoveFact)}");

            if (SecurityConfiguration.IsDebugModeEnabled)
            {
                SecurityProvider.Trace($"   Removing fact: {fact}");
            }

            var facts = System.IO.File.ReadAllLines(_factsFileFullName);

            if (!facts.Contains(fact))
            {
                SecurityProvider.Trace("   Fact already removed: nothing to do.");
                return;
            }

            SecurityProvider.Trace("   Removing fact...");
            System.IO.File.WriteAllLines(_factsFileFullName, facts.Where(f => f != fact));
            LoadEngine();
        }

        public virtual bool IsAuthorized(PermissionRequest request)
        {
            SecurityProvider.Trace($"Call to {nameof(IsAuthorized)}");

            try
            {
                return Eval(DefaultRuleName,
                    request.User,
                    request.Target,
                    request.Entity,
                    request.Action);
            }
            catch (Exception ex)
            {
                SecurityProvider.Trace($"   Error: {ex.GetFullMessage()}");
            }

            return false;
        }

        /// <summary>
        /// Renvoie la liste du trigramme des utilisateurs autorisé pour un utilisateur, une action et une entitée donnés.
        /// </summary>
        /// <param name="request">La requête à fournir au moteur prolog : User, Action, Entity doivent être non nulls</param>
        /// <param name="request.User>">Non Null</param>
        /// <param name="request.Target>">Ignoré</param>
        /// <param name="request.Action>">Non Null</param>
        /// <param name="request.Entity>">Non Null</param>
        /// <returns>Un tableau des utilisateurs authorisés</returns>
        public virtual List<string> GetAuthorizedTargets(PermissionRequest request)
        {
            SecurityProvider.Trace($"Call to {nameof(GetAuthorizedTargets)}");

            if (request == null)
                throw new ArgumentNullException(nameof(request));

            try
            {
                AssertIsNotNull(request.User, nameof(request.User));
                AssertIsNotNull(request.Action, nameof(request.Action));
                AssertIsNotNull(request.Entity, nameof(request.Entity));

                QuotePermissionRequest(ref request);

                var solutions = Solve(DefaultRuleName,
                    request.User,
                    "Target",
                    request.Entity,
                    request.Action);

                var collabs = solutions.Select(s => s["Target"].Trim('\''));

                return collabs.ToList();
            }
            catch (Exception ex)
            {
                SecurityProvider.Trace($"   Error: {ex.GetFullMessage()}");
                return null;
            }
        }

        /// <summary>
        /// Renvoie un objet Permission contenant les actions autorisées pour un utilisateur, sur une target et une entitée donnée.
        /// </summary>
        /// <param name="request">La requête à fournir au moteur prolog : User, Target, Entity doivent être non nulls</param>
        /// <param name="request.User>">Non Null</param>
        /// <param name="request.Target>">Non Null</param>
        /// <param name="request.Action>">Ignoré</param>
        /// <param name="request.Entity>">Non Null</param>
        /// <returns>Une Permission contenant les actions autorisées</returns>
        public virtual Permission GetTargetPermissions(PermissionRequest request)
        {
            SecurityProvider.Trace($"Call to {nameof(GetTargetPermissions)}");

            if (request == null)
                throw new ArgumentNullException(nameof(request));

            try
            {
                AssertIsNotNull(request.User, nameof(request.User));
                AssertIsNotNull(request.Entity, nameof(request.Entity));

	            var permission = new Permission
	            {
		            Target = request.Target,
		            Entity = request.Entity,
	            };

				QuotePermissionRequest(ref request);

                var solutions = Solve(DefaultRuleName,
                    request.User,
                    request.Target,
                    request.Entity,
                    "Action");

                var access = solutions
                    .Aggregate(AccessTypes.None,
                    (accessType, solution) => accessType | ActionToAccessType(solution["Action"]));

                // Aucune Permission
	            permission.AccessTypes = access;

                return permission;
            }
            catch (Exception ex)
            {
                SecurityProvider.Trace($"   Error: {ex.GetFullMessage()}");
            }

            return null;
        }

        public virtual List<string> GetEntityTargetPermissions(PermissionRequest request)
        {
            var solutions = Solve(DefaultRuleName,
                request.User,
                null,
                request.Target,
                request.Entity,
                "Action");

            var authorizedActions = solutions
                .Select(s => s["Action"])
                .Distinct()
                .Where(action => Actions.Contains(action));

            return authorizedActions.ToList();
        }

        /// <summary>
        /// Methode qui permet de récupérer toute les authorisations pour un utilisateur donné
        /// Authorisation(rma, G, E, A) permet par exemple de récupérer tous les couples (G, E, A) de solutions pour laquelle Authorisation(rma, G, E, A) est vraie
        /// </summary>
        /// <param name="request"> Action, Entite et Target sont ignoré, User doit être non null</param>
        /// <returns>  </returns>
        public virtual List<Permission> GetUserPermissions(PermissionRequest request)
        {
            SecurityProvider.Trace($"Call to {nameof(GetUserPermissions)}");

            if (request == null)
                throw new ArgumentNullException(nameof(request));

            try
            {
                AssertIsNotNull(request.User, nameof(request.User));

                var solutions = Solve(DefaultRuleName,
                    request.User,
                    "Target",
                    "Entity",
                    "Action");

                var permissions = solutions
	                .GroupBy(solution => new {Target = solution["Target"], Entity = solution["Entity"]})
	                .Select(accessGroup => new Permission
	                {
		                Target = accessGroup.Key.Target,
		                Entity = accessGroup.Key.Entity,
		                AccessTypes = accessGroup.Select(solution => solution["Action"])
			                .Aggregate(AccessTypes.None, (accessType, action) => accessType | ActionToAccessType(action))
	                });

                return permissions.ToList();
            }
            catch (Exception ex)
            {
                SecurityProvider.Trace($"   Error: {ex.GetFullMessage()}");
            }

            return null;
        }

        public virtual void Fetch()
        {
            SecurityProvider.Trace($"Call to {nameof(Fetch)}");
            LoadEngine();
        }

	    public static string BuildPredicate(string functor, params string[] arguments)
        {
            var terms = arguments.Select(arg => arg.AsTerm());
            var termList = string.Join(", ", terms);
            return functor + "(" + termList + ").";
        }

        private void LoadEngine()
        {
            SecurityProvider.Trace($"Call to {nameof(LoadEngine)}");

            try
            {
                // Construction des chemins relatifs
                SecurityProvider.Trace(_rulesFileFullName + " --- " + _factsFileFullName);

                PrologEngine = new PrologEngine(false);
                PrologEngine.Consult(_factsFileFullName);
                PrologEngine.Consult(_rulesFileFullName);
            }
            catch (Exception ex)
            {
                SecurityProvider.Trace($"   Error: {ex.GetFullMessage()}");
            }
        }

		#endregion

		#region Helpers

	    protected static void QuotePermissionRequest(ref PermissionRequest p)
	    {
		    p.Target = p.Target.Quote();
		    p.Entity = p.Entity.Quote();
		    p.Action = p.Action.Quote();
		    p.User = p.User.Quote();
	    }

	    private static void AssertIsNotNull(string value, string propertyName)
	    {
		    if (value == null)
		    {
			    throw new ArgumentException(propertyName + " can not be empty or whitespace.",
				    propertyName);
		    }
	    }

		private static AccessTypes ActionToAccessType(string action)
		{
			switch (action)
			{
				case ActionLecture: return AccessTypes.Read;
				case ActionAjouter: return AccessTypes.Create;
				case ActionModifier: return AccessTypes.Update;
				case ActionSupprimer: return AccessTypes.Delete;
				default: return AccessTypes.None;
			}
		}

	    #endregion Helpers


	}
}
