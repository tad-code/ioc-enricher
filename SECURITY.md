# Politique de sécurité

## Signaler une vulnérabilité

Ce projet est un projet pédagogique. Si vous découvrez une faille,
merci d'ouvrir une *issue* privée (« Report a vulnerability ») sur le dépôt
GitHub plutôt qu'une issue publique.

## Mesures en place

| Domaine | Mesure |
|---|---|
| Secrets | Aucune clé dans le code. Variables d'environnement uniquement (`.env` en local, *Environment Variables* en production). `.env` exclu par `.gitignore`. |
| Base de données | Règles RLS activées et **fermées** au rôle public : seule l'application (côté serveur) accède à la table, avec une clé secrète. |
| Dépendances | Versions épinglées, alertes et mises à jour Dependabot activées, `pip-audit` conseillé avant livraison. |
| En-têtes HTTP | HSTS, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, CSP restrictive. |
| Entrées | Validation stricte du type d'IOC, taille maximale de la requête (16 Ko) et de la saisie (512 caractères). |
| Erreurs | Messages lisibles pour l'utilisateur, détails techniques uniquement côté journal serveur. |
| Supervision | Route `/health` réduite au strict minimum (aucune information de configuration). |

## Bonnes pratiques pour un contributeur

1. Ne jamais committer de fichier `.env`, de clé API ni de mot de passe.
2. Utiliser une clé secrète côté serveur, jamais dans du code servi au navigateur.
3. Lancer `python -m pytest` et `pip-audit` avant toute publication.
