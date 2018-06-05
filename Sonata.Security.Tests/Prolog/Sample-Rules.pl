entite("collaborateur").

action("lecture").
action("ajouter").
action("supprimer").
action("modifier").

authorisation(Utilisateur,_,"collaborateur",Action):-admin(Utilisateur),action(Action).
authorisation(_,_,"collaborateur","lecture"):-true.