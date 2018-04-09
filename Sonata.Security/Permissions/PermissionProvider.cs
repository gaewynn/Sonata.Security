#region Namespace Sonata.Security.Permission
//	TODO
#endregion

using Sonata.Core.Extensions;
using Sonata.Security.Extensions;
using System;
using System.Collections.Generic;
using System.Linq;
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

		public PrologEngine PrologEngine { get; set; }

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

		public virtual bool Eval(string ruleName = DefaultRuleName, params string[] arguments)
		{
			SecurityProvider.Trace($"Call to {nameof(Eval)}");

			try
			{
				var goal = $"{ruleName}({String.Join(", ", arguments.Select(arg => arg.AsTerm()))}).";
				if (SecurityConfiguration.IsDebugModeEnabled)
					SecurityProvider.Trace($"   Running predicate: {goal}");

				var result = PrologEngine.GetFirstSolution(goal);
				return result.Solved;
			}
			catch (Exception ex)
			{
				SecurityProvider.Trace($"   Error: {ex.GetFullMessage()}");
			}

			return false;
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
				var goal = BuildGenericPermissionQuestion(request);
				if (goal == null)
				{
					SecurityProvider.Trace("   Built goal is null: no predicate to run");
					return false;
				}

				SecurityProvider.Trace("   Running predicate...");

				var reponse = PrologEngine.GetFirstSolution(goal);
				return reponse.Solved;
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
				//	Vérifie que User, Action, Entity non null
				var neededKeys = new[] { "User", "Action", "Entity" };
				foreach (var key in neededKeys)
				{
					if (String.IsNullOrWhiteSpace(request.GetPropertyValue(request.GetType(), key) as String))
						throw new ArgumentException(key + " can not be empty or whitespace.", key);
				}


				QuotePermissionRequest(ref request);
				request.Target = "Collab";
				var goal = BuildGenericPermissionQuestion(request);

				SecurityProvider.Trace(goal == null
					? "   Built goal is null: no predicate to run"
					: "   Running predicate...");

				var solveResults = PrologEngine.GetAllSolutions(null, goal);
				var returnedCollabs = new List<string>();
				
				if (!solveResults.Success)
					return returnedCollabs;

				returnedCollabs.AddRange(solveResults.NextSolution.Select(solution => solution.NextVariable.Single(e => e.Name == "Collab").Value));

				return returnedCollabs;
			}
			catch (Exception ex)
			{
				SecurityProvider.Trace($"   Error: {ex.GetFullMessage()}");
			}

			return null;
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
				//Vérifie que User, Target et Entity sont non nulls
				var neededKeys = new[] { "User", "Entity" };
				foreach (var key in neededKeys)
				{
					if (String.IsNullOrWhiteSpace(request.GetPropertyValue(request.GetType(), key) as String))
						throw new ArgumentException(key + " can not be empty or whitespace.", key);
				}

				QuotePermissionRequest(ref request);
				request.Action = "A";
				var goal = BuildGenericPermissionQuestion(request);

				SecurityProvider.Trace(goal == null
					? "   Built goal is null: no predicate to run"
					: "   Running predicate...");

				var solveResults = PrologEngine.GetAllSolutions(null, goal);

				// Aucune Permission
				var returnedPermission = new Permission
				{
					Target = request.Target,
					Entity = request.Entity
				};

				if (!solveResults.Success)
					return returnedPermission;

				foreach (var solution in solveResults.NextSolution)
				{
					var action = solution.NextVariable.Single(e => e.Name == request.Action).Value;
					switch (action)
					{
						case ActionLecture:
							returnedPermission.AccessTypes |= AccessTypes.Read;
							break;
						case ActionAjouter:
							returnedPermission.AccessTypes |= AccessTypes.Create;
							break;
						case ActionModifier:
							returnedPermission.AccessTypes |= AccessTypes.Update;
							break;
						case ActionSupprimer:
							returnedPermission.AccessTypes |= AccessTypes.Delete;
							break;
					}
				}

				return returnedPermission;
			}
			catch (Exception ex)
			{
				SecurityProvider.Trace($"   Error: {ex.GetFullMessage()}");
			}

			return null;
		}

		public virtual List<string> GetEntityTargetPermissions(PermissionRequest request)
		{
			var rights = new List<string>();
			for (var index = 0; index < Actions.Count; index++)
			{
				var goal = $"{DefaultRuleName}(" +
						   $"{request.User.Quote()}, " +
						   "\"_\", " +
						   $"{request.Target.Quote()}, " +
						   $"{request.Entity.Quote()}, " +
						   $"{Actions.ElementAt(index).Quote()}).";
				
				var reponse = PrologEngine.GetFirstSolution(goal);
				if (reponse.Solved)
					rights.Add(Actions.ElementAt(index));
			}

			return rights;
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
				//Vérifie que User, Target et Entity sont non nulls
				var neededKeys = new[] { "User" };
				foreach (var key in neededKeys)
				{
					if (String.IsNullOrWhiteSpace(request.GetPropertyValue(request.GetType(), key) as String))
						throw new ArgumentException(key + " can not be empty or whitespace.", key);
				}

				request.Action = "A";
				request.Entity = "E";
				request.Target = "T";

				var goal = BuildGenericPermissionQuestion(request);

				SecurityProvider.Trace(goal == null
					? "   Built goal is null: no predicate to run"
					: "   Running predicate...");

				var solveResults = PrologEngine.GetAllSolutions(null, goal);

				// Aucune Permission
				var returnedPermission = new List<Permission>();
				if (!solveResults.Success)
					return returnedPermission;

				returnedPermission.AddRange(solveResults.NextSolution.Select(solution => new Permission
				{
					Target = solution.NextVariable.Single(e => e.Name == request.Target).Value,
					Entity = solution.NextVariable.Single(e => e.Name == request.Entity).Value,
					AccessTypes = solution.NextVariable.SingleOrDefault(e => e.Name == request.Action)?.Value.GetEnumStringValue<AccessTypes>() ?? AccessTypes.None
				}));

				//Aggregation des accesstypes
				return returnedPermission
					.GroupBy(a => a.Target + a.Entity)
					.Select(
						list =>
						{
							var entityTarget = list.FirstOrDefault();
							var aggregateAccessType = list.Select(q => q.AccessTypes).Aggregate(AccessTypes.None, (sum, nxtElt) =>
							{
								sum |= nxtElt;
								return sum;
							});
							return new Permission()
							{
								Entity = entityTarget.Entity,
								Target = entityTarget.Target,
								AccessTypes = aggregateAccessType
							};
						})
					.ToList();
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

		public virtual string BuildGenericPermissionQuestion(PermissionRequest request)
		{
			SecurityProvider.Trace($"Call to {nameof(BuildGenericPermissionQuestion)}");

			try
			{
				var predicate = $"{DefaultRuleName}(" +
								$"{request.User.AsTerm()}" +
								$"{request.Target.AsTerm()}" +
								$"{request.Entity.AsTerm()}" +
								$"{request.Action.AsTerm()}";

				if (SecurityConfiguration.IsDebugModeEnabled)
					SecurityProvider.Trace($"   Building predicate: {predicate}");

				return predicate;
			}
			catch (Exception ex)
			{
				SecurityProvider.Trace($"   Error: {ex.GetFullMessage()}");
			}

			return null;
		}

		protected void QuotePermissionRequest(ref PermissionRequest p)
		{
			p.Target = p.Target.Quote();
			p.Entity = p.Entity.Quote();
			p.Action = p.Action.Quote();
			p.User = p.User.Quote();
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
	}
}
