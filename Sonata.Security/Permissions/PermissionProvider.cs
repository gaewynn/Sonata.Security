#region Namespace Sonata.Security.Permission
//	TODO
#endregion

using alice.tuprolog;
using Sonata.Core.Extensions;
using Sonata.Security.Extensions;
using System;
using System.Collections.Generic;
using System.Linq;
using jio = java.io;

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

		private readonly string _factsFileFullName;
		private readonly string _rulesFileFullName;
		protected string Entity;
		protected Term PermissionCheck;
		private readonly List<string> _actions = new List<string> { ActionLecture, ActionAjouter, ActionModifier, ActionSupprimer };

		#endregion

		#region Properties

		public Prolog PrologEngine { get; set; }

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

		public virtual bool RunRule(string ruleName = DefaultRuleName, params string[] arguments)
		{
			SecurityProvider.Trace($"Call to {nameof(RunRule)}");

			try
			{
				var goal = new Struct(ruleName, arguments.Select(arg => arg.AsTerm()).ToArray());
				if (SecurityConfiguration.IsDebugModeEnabled)
				{
					SecurityProvider.Trace($"   Running predicate: {goal.toString()}");
				}
				var result = PrologEngine.solve(goal);
				return result.isSuccess();
			}
			catch (Exception ex)
			{
				SecurityProvider.Trace($"   Error: {ex.GetFullMessage()}");
				if (ex is MalformedGoalException malFormedGoalException)
					malFormedGoalException.printStackTrace();
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

				var reponse = PrologEngine.solve(goal);
				return reponse.isSuccess();
			}
			catch (Exception ex)
			{
				SecurityProvider.Trace($"   Error: {ex.GetFullMessage()}");
				if (ex is MalformedGoalException malFormedGoalException)
					malFormedGoalException.printStackTrace();
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
				Term goal = BuildGenericPermissionQuestion(request);

				SecurityProvider.Trace(goal == null 
					? "   Built goal is null: no predicate to run" 
					: "   Running predicate...");

				var solveResult = PrologEngine.solve(goal);
				var returnedCollabs = new List<string>();

				if (!solveResult.isSuccess())
					return returnedCollabs;

				while (solveResult.isSuccess())
				{
					returnedCollabs.Add(solveResult.getTerm("Collab")?.ToString()?.Trim('\''));
					try
					{
						solveResult = PrologEngine.solveNext();
					}
					catch (NoMoreSolutionException ex)
					{
						SecurityProvider.Trace($"   Error: {ex.GetFullMessage()}");
						break;
					}
				}

				return returnedCollabs;
			}
			catch (Exception ex)
			{
				SecurityProvider.Trace($"   Error: {ex.GetFullMessage()}");
				if (ex is MalformedGoalException malFormedGoalException)
					malFormedGoalException.printStackTrace();
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
				Term goal = BuildGenericPermissionQuestion(request);

				SecurityProvider.Trace(goal == null 
					? "   Built goal is null: no predicate to run" 
					: "   Running predicate...");

				var solveResult = PrologEngine.solve(goal);

				// Aucune Permission
				var returnedPermission = new Permission
				{
					Target = request.Target,
					Entity = request.Entity
				};

				if (!solveResult.isSuccess())
					return returnedPermission;

				while (solveResult.isSuccess())
				{
					try
					{
						switch (solveResult.getTerm(request.Action).toString())
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

						solveResult = PrologEngine.solveNext();
					}
					catch (NoMoreSolutionException ex)
					{
						SecurityProvider.Trace($"   Error: {ex.GetFullMessage()}");
						break;
					}
				}

				return returnedPermission;
			}
			catch (Exception ex)
			{
				SecurityProvider.Trace($"   Error: {ex.GetFullMessage()}");
				if (ex is MalformedGoalException malFormedGoalException)
					malFormedGoalException.printStackTrace();
			}

			return null;
		}

		public virtual List<string> GetEntityTargetPermissions(PermissionRequest request)
		{
			var rights = new List<string>();
			for (var index = 0; index < _actions.Count; index++)
			{
				var goal = new Struct(DefaultRuleName, Term.createTerm(request.User.Quote()), Term.createTerm("_"),
					Term.createTerm(request.Target.Quote()), Term.createTerm(request.Entity.Quote()),
					Term.createTerm(_actions.ElementAt(index).Quote()));

				var reponse = PrologEngine.solve(goal);
				if (reponse.isSuccess())
					rights.Add(_actions.ElementAt(index));
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

				Term goal = BuildGenericPermissionQuestion(request);

				SecurityProvider.Trace(goal == null 
					? "   Built goal is null: no predicate to run" 
					: "   Running predicate...");

				var solveResult = PrologEngine.solve(goal);

				// Aucune Permission
				var returnedPermission = new List<Permission>();
				if (!solveResult.isSuccess())
					return returnedPermission;

				while (solveResult.isSuccess())
				{
					try
					{
						solveResult = PrologEngine.solveNext();
						returnedPermission.Add(new Permission
						{
							Target = solveResult.getTerm(request.Target).toString(),
							Entity = solveResult.getTerm(request.Entity).toString(),
							AccessTypes = solveResult.getTerm(request.Action)?.toString().GetEnumStringValue<AccessTypes>() ?? AccessTypes.None
						});
					}
					catch (NoMoreSolutionException ex)
					{
						SecurityProvider.Trace($"   Error: {ex.GetFullMessage()}");
						break;
					}
				}

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
				if (ex is MalformedGoalException malFormedGoalException)
					malFormedGoalException.printStackTrace();
			}

			return null;
		}

		public virtual void Fetch()
		{
			SecurityProvider.Trace($"Call to {nameof(Fetch)}");
			LoadEngine();
		}

		public virtual Struct BuildGenericPermissionQuestion(PermissionRequest request)
		{
			SecurityProvider.Trace($"Call to {nameof(BuildGenericPermissionQuestion)}");

			try
			{
				var predicate = new Struct(DefaultRuleName,
					request.User.AsTerm(),
					request.Target.AsTerm(),
					request.Entity.AsTerm(),
					request.Action.AsTerm());

				if (SecurityConfiguration.IsDebugModeEnabled)
				{
					SecurityProvider.Trace($"   Building predicate: {predicate.toString()}");
				}

				return predicate;
			}
			catch (Exception ex)
			{
				SecurityProvider.Trace($"   Error: {ex.GetFullMessage()}");
				if (ex is MalformedGoalException malFormedGoalException)
					malFormedGoalException.printStackTrace();
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

				jio.InputStream streamData = new jio.ByteArrayInputStream(System.IO.File.ReadAllBytes(_factsFileFullName));
				jio.InputStream streamRegles = new jio.ByteArrayInputStream(System.IO.File.ReadAllBytes(_rulesFileFullName));

				var theorieData = new Theory(streamData);
				var theorieRegles = new Theory(streamRegles);

				//moteur prolog
				PrologEngine = new Prolog();
				PrologEngine.setTheory(theorieData);
				PrologEngine.addTheory(theorieRegles);

				streamData.close();
				streamRegles.close();
			}
			catch (jio.FileNotFoundException fex)
			{
				SecurityProvider.Trace($"   Error: {fex.GetFullMessage()}");
				fex.printStackTrace();
			}
			catch (InvalidTheoryException iex)
			{
				SecurityProvider.Trace($"   Error: {iex.GetFullMessage()}");
				iex.printStackTrace();
			}
			catch (Exception ex)
			{
				SecurityProvider.Trace($"   Error: {ex.GetFullMessage()}");
			}
		}

		#endregion
	}
}
