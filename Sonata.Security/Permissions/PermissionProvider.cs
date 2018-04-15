#region Namespace Sonata.Security.Permission
//	TODO
#endregion

using Prolog;
using Sonata.Core.Extensions;
using Sonata.Security.Extensions;
using System;
using System.Collections.Generic;
using System.Linq;

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
		public const string TermTarget = "Target";
		public const string TermAction = "Action";
		public const string TermEntity = "Entity";

		#endregion

		#region Members

		protected readonly List<string> Actions = new List<string> { ActionLecture, ActionAjouter, ActionModifier, ActionSupprimer };
		private readonly List<TermType> _solveResultsRefiners = new List<TermType> {TermType.Atom, TermType.String, TermType.Number};
		private readonly string _factsFileFullName;
		private readonly string _rulesFileFullName;
		private readonly PrologEngine _prologEngine;

		#endregion

		#region Constructors

		public PermissionProvider(string factsFileFullName, string rulesFileFullName)
		{
			_factsFileFullName = factsFileFullName;
			_rulesFileFullName = rulesFileFullName;
			_prologEngine = new PrologEngine(false);

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
				SecurityProvider.Trace($"   Running predicate: {goal}");

				var result = _prologEngine.GetFirstSolution(goal);
				return result.Solved;
			}
			catch (Exception ex)
			{
				SecurityProvider.Trace($"   Error: {ex.GetFullMessage()}");
				throw;
			}
		}

		public virtual IEnumerable<Solution> Solve(string predicate, params string[] terms)
		{
			SecurityProvider.Trace($"Call to {nameof(Solve)}({predicate}, {(terms == null ? "null" : String.Join(", ", terms))})");
			return Solve(true, predicate, terms);
		}

		/// <summary>
		/// Evaluate a partially bound predicate (with Prolog variables) and returns the solutions as a collection of dictionaries.
		/// </summary>
		/// <param name="refineResults"></param>
		/// <param name="predicate"></param>
		/// <param name="terms"></param>
		/// <returns></returns>
		public virtual IEnumerable<Solution> Solve(bool refineResults, string predicate, params string[] terms)
		{
			SecurityProvider.Trace($"Call to {nameof(Solve)}");
			try
			{
				var goal = BuildPredicate(predicate, terms);
				SecurityProvider.Trace($"   Running predicate: {goal}");
				
				var solveResults = _prologEngine.GetAllSolutions(goal, _factsFileFullName, _rulesFileFullName);
				if (!solveResults.Success)
					return new List<Solution>();

				var solutions = solveResults.NextSolution
					.Select(solution => new Solution(solution.NextVariable
						.Select(variable => new Term
						{
							Type = variable.Type,
							Name = variable.Name,
							Value = variable.Value
						})));

				return refineResults
					? solutions.Where(e => e.Any(t => _solveResultsRefiners.Contains((TermType)Enum.Parse(typeof(TermType), t.Type, true))))
					: solutions;
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
			SecurityProvider.Trace($"   Adding fact: {fact}");

			AddFacts(new List<string> { fact });
		}

		public virtual void AddFacts(IEnumerable<string> facts)
		{
			SecurityProvider.Trace($"Call to {nameof(AddFacts)}");

			if (facts == null)
				return;

			var addedFacts = facts as string[] ?? facts.ToArray();
			SecurityProvider.Trace($"   Adding facts: {String.Join("; ", addedFacts)}");

			AddPredicates(addedFacts, _factsFileFullName);
		}

		public virtual void RemoveFact(string fact)
		{
			SecurityProvider.Trace($"Call to {nameof(RemoveFact)}");
			SecurityProvider.Trace($"   Removing fact: {fact}");

			RemoveFacts(new List<string> { fact });
		}

		public virtual void RemoveFacts(IEnumerable<string> facts)
		{
			SecurityProvider.Trace($"Call to {nameof(RemoveFacts)}");

			var removedFacts = facts as string[] ?? facts.ToArray();
			SecurityProvider.Trace($"   Removing facts: {String.Join("; ", removedFacts)}");

			RemovePredicates(removedFacts, _factsFileFullName);
		}

		public virtual void AddRule(string rule)
		{
			SecurityProvider.Trace($"Call to {nameof(AddRule)}");
			SecurityProvider.Trace($"   Adding rule: {rule}");

			AddRules(new List<string> { rule });
		}

		public virtual void AddRules(IEnumerable<string> rules)
		{
			SecurityProvider.Trace($"Call to {nameof(AddRules)}");

			var addedRules = rules as string[] ?? rules.ToArray();
			SecurityProvider.Trace($"   Adding rules: {String.Join("; ", addedRules)}");

			AddPredicates(addedRules, _rulesFileFullName);
		}

		public virtual void RemoveRule(string rule)
		{
			SecurityProvider.Trace($"Call to {nameof(RemoveRule)}");
			SecurityProvider.Trace($"   Removing rule: {rule}");

			RemoveRules(new List<string> { rule });
		}

		public virtual void RemoveRules(IEnumerable<string> rules)
		{
			SecurityProvider.Trace($"Call to {nameof(RemoveRules)}");

			var removedRules = rules as string[] ?? rules.ToArray();
			SecurityProvider.Trace($"   Removing rules: {String.Join("; ", removedRules)}");

			RemovePredicates(removedRules, _rulesFileFullName);
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
		public virtual IEnumerable<string> GetAuthorizedTargets(PermissionRequest request)
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
					TermTarget,
					request.Entity,
					request.Action);
				
				return solutions.Select(solution => solution.GetTermValue(TermTarget).Trim('\''));
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
					TermAction);

				var access = solutions
					.Aggregate(AccessTypes.None,
					(accessType, solution) => accessType | ActionToAccessType(solution.GetTermValue(TermAction)));

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

		public virtual IEnumerable<string> GetEntityTargetPermissions(PermissionRequest request)
		{
			var solutions = Solve(DefaultRuleName,
				request.User,
				null,
				request.Target,
				request.Entity,
				TermAction);

			return solutions
				.Select(s => s.GetTermValue(TermAction))
				.Distinct()
				.Where(action => Actions.Contains(action));
		}

		/// <summary>
		/// Methode qui permet de récupérer toute les authorisations pour un utilisateur donné
		/// Authorisation(rma, G, E, A) permet par exemple de récupérer tous les couples (G, E, A) de solutions pour laquelle Authorisation(rma, G, E, A) est vraie
		/// </summary>
		/// <param name="request"> Action, Entite et Target sont ignoré, User doit être non null</param>
		/// <returns>  </returns>
		public virtual IEnumerable<Permission> GetUserPermissions(PermissionRequest request)
		{
			SecurityProvider.Trace($"Call to {nameof(GetUserPermissions)}");

			if (request == null)
				throw new ArgumentNullException(nameof(request));

			try
			{
				AssertIsNotNull(request.User, nameof(request.User));

				var solutions = Solve(DefaultRuleName,
					request.User,
					TermTarget,
					TermEntity,
					TermAction);

				return solutions
					.GroupBy(solution => new { Target = solution.GetTermValue(TermTarget), Entity = solution.GetTermValue(TermEntity) })
					.Select(accessGroup => new Permission
					{
						Target = accessGroup.Key.Target,
						Entity = accessGroup.Key.Entity,
						AccessTypes = accessGroup
							.Select(solution => solution.GetTermValue(TermAction))
							.Aggregate(AccessTypes.None, (accessType, action) => accessType | ActionToAccessType(action))
					});
			}
			catch (Exception ex)
			{
				SecurityProvider.Trace($"   Error: {ex.GetFullMessage()}");
			}

			return null;
		}

		public static string BuildPredicate(string functor, params string[] arguments)
		{
			var terms = arguments.Select(arg => arg.AsTerm());
			var termList = string.Join(", ", terms);
			return functor + "(" + termList + ").";
		}

		private void Reset()
		{
			_prologEngine.Reset();
			_prologEngine.Consult(_factsFileFullName);
			_prologEngine.Consult(_rulesFileFullName);
		}

		private void AddPredicates(IEnumerable<string> predicates, string file)
		{
			SecurityProvider.Trace($"Call to {nameof(AddPredicates)}");

			var addedPredicates = predicates as string[] ?? predicates.ToArray();
			SecurityProvider.Trace($"   Adding predicates: {String.Join("; ", addedPredicates)}");

			var filePredicates = System.IO.File.ReadAllLines(file).ToList();

			SecurityProvider.Trace("   Appending predicates...");
			foreach (var predicate in addedPredicates)
			{
				if (filePredicates.Contains(predicate))
					SecurityProvider.Trace($"   Predicate {predicate} already exists: nothing to do.");
				else
					filePredicates.Add(predicate);
			}

			System.IO.File.WriteAllLines(file, filePredicates);
			Reset();
		}

		private void RemovePredicates(IEnumerable<string> predicates, string file)
		{
			SecurityProvider.Trace($"Call to {nameof(RemovePredicates)}");

			var removedPredicates = predicates as string[] ?? predicates.ToArray();
			SecurityProvider.Trace($"   Removing predicates: {String.Join("; ", removedPredicates)} from file {file}");

			var filePredicates = System.IO.File.ReadAllLines(file).ToList();

			SecurityProvider.Trace("   Removing predicates...");
			foreach (var predicate in removedPredicates)
			{
				var predicateIndex = filePredicates.IndexOf(predicate);
				if (predicateIndex < 0)
					SecurityProvider.Trace($"   Predicate {predicate} already removed: nothing to do.");
				else
					filePredicates.RemoveAt(predicateIndex);
			}

			System.IO.File.WriteAllLines(file, filePredicates);
			Reset();
		}

		#endregion

		#region Helpers

		protected static void QuotePermissionRequest(ref PermissionRequest request)
		{
			request.Target = request.Target.Quote();
			request.Entity = request.Entity.Quote();
			request.Action = request.Action.Quote();
			request.User = request.User.Quote();
		}

		private static void AssertIsNotNull(string value, string propertyName)
		{
			if (value == null)
			{
				throw new ArgumentException(
					$"{propertyName} can not be empty or whitespace.",
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
