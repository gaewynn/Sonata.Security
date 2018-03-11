#region Namespace Sonata.Security.Permission
//	TODO
#endregion

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using alice.tuprolog;
using java.io;
using Sonata.Core.Extensions;
using Sonata.Diagnostics.Logs;

namespace Sonata.Security.Permissions
{
	public class PermissionProvider
	{
		#region Constants

		protected const string GenericAuthorisationRuleName = "authorisation";

		#endregion

		#region Members

		private readonly string _factsFileFullName;
		private readonly string _rulesFileFullName;
		protected string Entity;
		protected Term PermissionCheck;

		#endregion

		#region Properties

		public List<string> Actions { get; set; }

		public Prolog PrologEngine { get; set; }

		#endregion

		#region Constructors

		public PermissionProvider(string factsFileFullName, string rulesFileFullName)
		{
			_factsFileFullName = factsFileFullName;
			_rulesFileFullName = rulesFileFullName;

			SecurityProvider.Trace($"Facts file: {_factsFileFullName}");
			SecurityProvider.Trace($"Rules file: {_rulesFileFullName}");

			Actions = new List<string>();
		}

		#endregion

		#region Methods

		public virtual bool RunRule(string ruleName, string[] arguments)
		{
			SecurityProvider.Trace($"Call to {nameof(RunRule)}");

			try
			{
				if (SecurityConfiguration.IsDebugModeEnabled)
				{
					var predicate = GenericAuthorisationRuleName;
					predicate += "(";

					foreach (var argument in arguments)
					{
						if (argument == null)
							predicate += "\"null\", ";
						else
							predicate += $"\"{argument}\", ";
					}

					predicate = predicate.TrimEnd(' ');
					predicate = predicate.TrimEnd(',');
					predicate += ").";

					SecurityProvider.Trace($"   Running predicate: {predicate}");
				}

				var goal = new Struct(GenericAuthorisationRuleName, arguments.Select(Term.createTerm).ToArray());
				var reponse = PrologEngine.solve(goal);
				if (reponse.isSuccess())
					return true;
			}
			catch (Exception ex)
			{
				SecurityProvider.Trace($"   Error: {ex.GetFullMessage()}");
				if (ex is MalformedGoalException malFormedGoalException)
					malFormedGoalException.printStackTrace();
			}

			return false;
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

				if (goal == null)
					SecurityProvider.Trace("   Built goal is null: no predicate to run");
				else
					SecurityProvider.Trace("   Running predicate...");

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

				if (goal == null)
					SecurityProvider.Trace("   Built goal is null: no predicate to run");
				else
					SecurityProvider.Trace("   Running predicate...");

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
							case "lecture":
								returnedPermission.AccessTypes |= AccessTypes.Read;
								break;
							case "ajouter":
								returnedPermission.AccessTypes |= AccessTypes.Create;
								break;
							case "modifier":
								returnedPermission.AccessTypes |= AccessTypes.Update;
								break;
							case "supprimer":
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
			SecurityProvider.Trace($"Call to {nameof(GetEntityTargetPermissions)}");

			try
			{
				var rights = new List<string>();
				for (var index = 0; index < Actions.Count; index++)
				{
					var goal = new Struct(GenericAuthorisationRuleName, Term.createTerm(Quote(request.User)), Term.createTerm("_"),
						Term.createTerm(Quote(request.Target)), Term.createTerm(Quote(request.Entity)),
						Term.createTerm(Quote(Actions.ElementAt(index))));

					if (SecurityConfiguration.IsDebugModeEnabled)
					{
						var predicate = GenericAuthorisationRuleName;
						predicate += "(";
						predicate += $"{Quote(request.User)}, ";
						predicate += $"_, ";
						predicate += $"{Quote(request.Target)}, ";
						predicate += $"{Quote(request.Entity)}, ";
						predicate += $"{Quote(Actions.ElementAt(index))}";
						predicate += ").";

						SecurityProvider.Trace($"   Running predicate: {predicate}");
					}

					var reponse = PrologEngine.solve(goal);
					if (reponse.isSuccess())
						rights.Add(Actions.ElementAt(index));
				}

				return rights;
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

				if (goal == null)
					SecurityProvider.Trace("   Built goal is null: no predicate to run");
				else
					SecurityProvider.Trace("   Running predicate...");

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
				var userTerm = String.IsNullOrEmpty(request.User) ? Term.createTerm("_") : Term.createTerm(request.User);
				var targetTerm = String.IsNullOrWhiteSpace(request.Target) ? Term.createTerm("_") : Term.createTerm(request.Target);
				var entityTerm = String.IsNullOrEmpty(request.Entity) ? Term.createTerm("_") : Term.createTerm(request.Entity);
				var actionTerm = String.IsNullOrEmpty(request.Action) ? Term.createTerm("_") : Term.createTerm(request.Action);

				if (SecurityConfiguration.IsDebugModeEnabled)
				{
					var predicate = GenericAuthorisationRuleName;
					predicate += "(";
					predicate = $"\"{(String.IsNullOrEmpty(request.User) ? "_" : request.User)}\", ";
					predicate = $"\"{(String.IsNullOrEmpty(request.Target) ? "_" : request.Target)}\", ";
					predicate = $"\"{(String.IsNullOrEmpty(request.Entity) ? "_" : request.Entity)}\", ";
					predicate = $"\"{(String.IsNullOrEmpty(request.Action) ? "_" : request.Action)}\").";

					SecurityProvider.Trace($"   Building predicate: {predicate}");
				}

				return new Struct(GenericAuthorisationRuleName, userTerm, targetTerm, entityTerm, actionTerm);
			}
			catch (Exception ex)
			{
				SecurityProvider.Trace($"   Error: {ex.GetFullMessage()}");
				if (ex is MalformedGoalException malFormedGoalException)
					malFormedGoalException.printStackTrace();
			}

			return null;
		}

		protected string Quote(string value)
		{
			return $"'{value}'";
		}

		protected void QuotePermissionRequest(ref PermissionRequest p)
		{
			p.Target = !String.IsNullOrWhiteSpace(p.Target) ? Quote(p.Target) : null;
			p.Entity = !String.IsNullOrWhiteSpace(p.Entity) ? Quote(p.Entity) : null;
			p.Action = !String.IsNullOrWhiteSpace(p.Action) ? Quote(p.Action) : null;
			p.User = !String.IsNullOrWhiteSpace(p.User) ? Quote(p.User) : null;
		}

		private void LoadEngine()
		{
			SecurityProvider.Trace($"Call to {nameof(LoadEngine)}");

			try
			{
				// Construction des chemins relatifs
				TechnicalLog.Debug(GetType(), _rulesFileFullName + " --- " + _factsFileFullName);
				InputStream streamData = new FileInputStream(_factsFileFullName);
				InputStream streamRegles = new FileInputStream(_rulesFileFullName);

				var theorieData = new Theory(streamData);
				var theorieRegles = new Theory(streamRegles);

				//moteur prolog
				PrologEngine = new Prolog();
				PrologEngine.setTheory(theorieData);
				PrologEngine.addTheory(theorieRegles);

				streamData.close();
				streamRegles.close();
			}
			catch (FileNotFoundException fex)
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
