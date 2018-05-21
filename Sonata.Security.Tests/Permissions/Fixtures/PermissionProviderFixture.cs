using Sonata.Security.Permissions;
using System;
using System.IO;

namespace Sonata.Security.Tests.Permissions.Fixtures
{
	public class PermissionProviderFixture : IDisposable
	{
		#region Properties

		public string FactsFilePath { get; set; }

		public string RulesFilePath { get; set;  }

		public PermissionProvider Provider { get; set; }

		public PermissionProvider SampleProvider { get; }

		#endregion

		#region Constructors

		public PermissionProviderFixture()
		{
			InitializePredicates();

			SampleProvider = new PermissionProvider(
				Path.Combine(Directory.GetParent(Directory.GetCurrentDirectory())?.Parent?.Parent?.FullName, "Prolog", "Sample-Facts.pl"),
				Path.Combine(Directory.GetParent(Directory.GetCurrentDirectory())?.Parent?.Parent?.FullName, "Prolog", "Sample-Rules.pl"));
		}

		#endregion

		#region Destructors

		~PermissionProviderFixture()
		{
			ReleaseUnmanagedResources();
		}

		#endregion

		#region Methods

		#region IDisposable Members

		public void Dispose()
		{
			ReleaseUnmanagedResources();
			GC.SuppressFinalize(this);
		}

		#endregion

		private void InitializePredicates()
		{
			string[] facts = {
				"powerUser(alice).",
				"powerUser(bob).",
				"administrator(bob).",
				"chuckNorris(chuck).",

				"homme(socrate).",
				"droid(r2d2).",

				"collab('afi').",
				"collab(lma).",

				"collab(afi, ge).",
				"collab(lma, ge).",
				"collab(obl, ls).",

				"responsableActivite(afi, \".A1\").",
				"responsableActivite(afi, 2).",
				"responsableActivite(afi, _).",

				"admin(jdl).",
				"admin(tng).",
				"admin(obl).",
				"admin(afi).",
				"admin(viq)."
			};

			string[] rules =
			{
				"authorisation(User, Target, stuff, Action):-userCanDoActionOnTarget(User, Action, Target).",
				"authorisation(Utilisateur, _, collaborateur, Action):-admin(Utilisateur),action(Action).",
				"authorisation(_, _, collaborateur, lecture):-true.",

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

				"mortel(Personne):-homme(Personne).",

				"entite(collaborateur).",
				"action(lecture).",
				"action(ajouter).",
				"action(supprimer).",
				"action(modifier)."
			};

			FactsFilePath = Path.GetTempFileName();
			RulesFilePath = Path.GetTempFileName();

			File.WriteAllLines(FactsFilePath, facts);
			File.WriteAllLines(RulesFilePath, rules);

			Provider = new PermissionProvider(FactsFilePath, RulesFilePath);
		}

		private void ReleaseUnmanagedResources()
		{
			if (FactsFilePath != null)
				File.Delete(FactsFilePath);

			if (RulesFilePath != null)
				File.Delete(RulesFilePath);
		}

		#endregion
	}
}
