# 🎤 Guide de soutenance — IOC Enricher (Projet 5)

Ce mémo t'aide à **défendre ton projet en le comprenant**. Lis-le une fois,
puis relis les encadrés en gras : c'est ce que le formateur écoutera.

---

## 1. Le pitch en 60 secondes (à savoir dire sans notes)

> « IOC Enricher est une application web Python. Un analyste SOC y saisit un
> indicateur de compromission — une adresse IP, un domaine ou un hash — ou
> plusieurs d'un coup (mode par lots). Le programme reconnaît tout seul le type
> d'indicateur, appelle des **API externes** qui renvoient du **JSON**, transforme
> ce JSON en **réputation, score de risque justifié et action recommandée**,
> **enregistre l'analyse dans Supabase** et l'affiche avec l'historique, un
> tableau de bord et un export CSV. Le tout est **déployé en ligne** sur Vercel :
> le formateur peut l'utiliser sans rien installer. »

Puis tu ouvres l'URL et tu fais une démonstration en direct. **Montre les 6 cas
de test** (section « Tests réalisés » du README).

---

## 2. Les 5 parties de la soutenance

### Partie 1 — Python : comment fonctionne ton programme ?

Le parcours d'une analyse, dans l'ordre (`app.py`, fonction `analyze`) :

| # | Étape | Fichier / fonction |
|---|---|---|
| 1 | L'utilisateur valide le formulaire → `POST /analyze` | `templates/index.html` |
| 2 | Le type de l'IOC est détecté et validé | `ioc_parser.parse_ioc()` |
| 3 | L'API externe est interrogée (JSON) | `enrichment.enrich()` |
| 4 | Les signaux sont convertis en score 0-100 | `scoring.compute_risk()` |
| 5 | La ligne est insérée dans Supabase | `db.save_analysis()` |
| 6 | La page est réaffichée avec le rapport + l'historique | `render_home()` |

**Pourquoi des fonctions séparées ?** Parce que chaque fichier a **une seule
responsabilité** : si l'API change, je ne touche qu'à `enrichment.py` ; si la
règle de score change, je ne touche qu'à `scoring.py`. Et surtout : je peux
**tester** `ioc_parser.py` et `scoring.py` sans Internet ni base de données
(c'est ce que font les 14 tests unitaires).

### Partie 2 — L'API

- **Quelle API ?** Une par type d'IOC : `ip-api.com` (IP), `rdap.org` (domaine),
  `hashlookup.circl.lu` (hash). Optionnellement `AbuseIPDB` pour la réputation.
- **Comment je l'appelle ?** `requests.get(url, headers=..., params=..., timeout=8)`
  → méthode `GET`, une URL d'endpoint, des paramètres, des en-têtes (dont
  `User-Agent`) et un **délai maximum** pour ne pas bloquer l'utilisateur.
- **Que contient la réponse ?** Du JSON : un objet avec des clés comme `country`,
  `proxy`, `hosting`, `status`.
- **Qu'est-ce que JSON ?** Un format texte clé/valeur pour échanger des données.
  `reponse.json()` le transforme en dictionnaire Python (`dict`).
- **Le code de statut ?** `200` = succès, `404` = inconnu du registre,
  `429` = quota dépassé, `401` = clé refusée. **Je les gère tous** : un 404 sur
  un domaine devient un *signal de risque*, pas une erreur qui plante la page.

### Partie 3 — Supabase

- **Pourquoi une base de données ?** Pour garder la trace des analyses, savoir si
  un IOC a déjà été vu, et pouvoir supprimer une entrée obsolète.
- **Quelle table ?** `ioc_analyses` (9 colonnes — voir README section 8).
- **Quelles données ?** L'IOC, son type, le niveau et le score de risque, l'API
  qui a répondu, les champs enrichis (`jsonb`), les raisons du score (`jsonb`) et
  la date.
- **Comment j'envoie les données ?** Supabase expose chaque table en **API REST** :
  un `POST` vers `/rest/v1/ioc_analyses` avec la clé dans les en-têtes `apikey`
  et `Authorization: Bearer`, et la ligne en JSON dans le corps de la requête.

### Partie 4 — Le Web

- **Comment l'utilisateur interagit ?** Un formulaire HTML (`<form method="post">`)
  avec un champ texte. Flask reçoit la donnée dans `request.form.get("ioc")`.
- **Que se passe-t-il après le clic ?** Le navigateur envoie une requête HTTP
  `POST /analyze` au serveur ; Flask exécute `analyze()`, puis renvoie une page
  HTML complète (rendu serveur avec le moteur de gabarits Jinja2).

### Partie 5 — Le déploiement

- **Où ?** Sur **Vercel** : https://ioc-enricher-delta.vercel.app
- **Comment ?** Le code est sur GitHub, puis `vercel --prod`. Vercel exécute
  `api/index.py`, un fichier qui importe simplement l'application Flask.
- **Les variables d'environnement ?** Saisies dans *Vercel → Project → Settings →
  Environment Variables* (`SUPABASE_URL`, `SUPABASE_ANON_KEY`). Elles ne sont
  jamais dans le code : en local elles viennent du fichier `.env`, qui est
  **exclu de Git** par `.gitignore`.

---

## 3. Le test surprise — les 4 demandes les plus probables

### ⚡ « Ajoute un bouton pour supprimer une analyse »

**Déjà fait.** Montre-le : bouton « Supprimer » dans l'historique →
`templates/index.html` (formulaire `POST /delete/{{ ligne.id }}`) →
`app.py` fonction `delete()` → `db.delete_analysis(row_id)` qui envoie
`DELETE /rest/v1/ioc_analyses?id=eq.<id>`.

### ⚡ « Ajoute une colonne dans ton historique »

Deux cas :

**a) Une donnée déjà en base** (ex. `created_at`) — dans
`templates/index.html`, dans le `<thead>` :

```html
<th>Date (UTC)</th>
```

et dans le `<tbody>` :

```html
<td class="mono">{{ ligne.created_at }}</td>
```

**b) Une donnée nouvelle** (ex. l'endpoint de l'API appelée) — il faut
1) l'ajouter au `save_analysis(...)` dans `app.py`, 2) l'ajouter à la colonne
`summary` (déjà en `jsonb`, donc aucun changement de base nécessaire) :

```html
<td class="mono">{{ ligne.summary.endpoint }}</td>
```

*(Astuce à dire : `summary` est en `jsonb`, donc je peux y ranger des champs
supplémentaires sans modifier la table.)*

### ⚡ « Que se passe-t-il si l'utilisateur entre une donnée vide ? »

Démonstration immédiate : clique sur *Enrichir* sans rien saisir.
La fonction `parse_ioc()` renvoie `{"ok": False, "error": "Aucune valeur saisie..."}`,
`app.py` affiche le message et répond **HTTP 400**. Aucun appel d'API, aucun
enregistrement, **aucune trace Python** — juste un message lisible.

### ⚡ « Explique-moi cette ligne de code »

Trois lignes à connaître par cœur :

```python
# ioc_parser.py — détection du type
if HEX_RE.match(candidate) and len(candidate) in HASH_ALGORITHMS:
```
> « Si la chaîne ne contient que de l'hexadécimal **et** que sa longueur est 32,
> 40 ou 64 caractères, alors c'est un hash MD5, SHA1 ou SHA256. »

```python
# scoring.py — calcul du score
total = max(0, min(100, total))
```
> « Je borne le score entre 0 et 100, même si les signaux additionnés dépassent
> 100 ou descendent sous zéro. »

```python
# db.py — appel à Supabase
reponse = requests.request(method, _endpoint(), params=params, json=payload,
                           headers=_headers(extra_headers), timeout=TIMEOUT)
```
> « J'envoie une requête HTTP à l'API REST de Supabase : la méthode (GET, POST ou
> DELETE), l'URL de la table, les paramètres de filtrage, le corps JSON et les
> en-têtes d'authentification, avec un délai maximum de 10 secondes. »

---

## 4. Dix questions rapides et leurs réponses

1. **Pourquoi Flask et pas Streamlit ?** Streamlit sert une page unique et
   s'exécute en continu ; Flask me donne des routes HTTP explicites
   (`GET /`, `POST /analyze`, `POST /delete/<id>`) — je peux expliquer chaque
   route — et il se déploie en *serverless*, ce qui rend l'application
   accessible depuis n'importe où, gratuitement.
2. **Pourquoi `requests` et pas une bibliothèque Supabase ?** `requests` suffit :
   Supabase expose une API REST standard. Le code est plus léger et surtout je
   vois exactement la requête HTTP qui part, donc je peux l'expliquer.
3. **Où sont mes clés ?** Dans les variables d'environnement, jamais dans le code.
   `.env` en local, *Environment Variables* sur Vercel. Le dépôt GitHub est propre.
4. **Que se passe-t-il si l'API ne répond pas ?** `enrichment._get()` attrape
   `Timeout` et `ConnectionError` et lève `EnrichmentError`. L'utilisateur voit
   « Enrichissement impossible (timeout) : … » et peut réessayer.
5. **Que se passe-t-il si Internet est coupé ?** Même mécanisme
   (`kind="network"`) ; l'application ne plante pas, la page reste utilisable.
6. **Et si l'enregistrement Supabase échoue ?** Le rapport **reste affiché** avec
   le bandeau « Analyse effectuée, mais NON enregistrée dans Supabase ». On ne
   perd pas le travail de l'analyste.
7. **Pourquoi un score de risque plutôt qu'un simple « oui/non » ?** Un IOC n'est
   jamais binaire : je pars d'une base de 10 points et chaque signal ajoute des
   points (proxy +35, datacenter +25, domaine de moins de 30 jours +30…), avec un
   bonus négatif si un signal est rassurant. Le score est **borné à 0-100**, puis
   traduit en **verdict de réputation** — `SAIN`, `DOUTEUX`, `SUSPECT`,
   `MALVEILLANT` — affiché en grand, et en **niveau de risque** (`LOW` à
   `CRITICAL`), et chaque point est **affiché avec sa justification**.
   *(Réputation = la conclusion lisible ; niveau de risque = la gradation technique.)*
8. **D'où vient ma liste de pays « à risque » ?** Des rapports publics de menace.
   C'est volontairement un signal **faible** (+10) : un pays n'est jamais une
   preuve, seulement un élément parmi d'autres.
9. **Comment tester sans Internet ?** `pytest` lance 24 tests qui n'ont besoin ni
   de réseau ni de base (ils testent la logique : détection, validation, score,
   action recommandée, découpe du mode par lots, statistiques).
10. **Comment ajouter un nouveau type d'IOC, par exemple une URL ?** J'ajoute la
    détection dans `ioc_parser.detect_type()`, une fonction
    `enrich_url()` dans `enrichment.py`, je l'ajoute au dictionnaire `repartition`
    de `enrich()`, et j'ajoute les règles correspondantes dans `scoring.py`.
    L'interface n'a pas besoin de changer : elle appelle toujours `enrich()`.
11. **Pourquoi une limite de 5 indicateurs par lot ?** Parce que Vercel limite le
    temps d'exécution d'une fonction (30 secondes ici). Au-delà de 5 appels d'API
    enchaînés, je risquais l'interruption en plein traitement. `analyser_lot()`
    surveille donc le temps écoulé (`time.monotonic()`) et rend un résultat
    partiel propre — les indicateurs non traités sont signalés plutôt que perdus.
    *Je préfère une limite assumée à un plantage silencieux.*
12. **À quoi sert l'API JSON, alors qu'il y a déjà l'interface ?** À l'intégration :
    un script, un tableur ou un futur outil de supervision peut appeler
    `/api/analyze?ioc=…` et récupérer le verdict en JSON, sans navigateur. C'est
    la même fonction Python qui travaille dans les deux cas.
13. **Comment le tableau de bord calcule-t-il ses statistiques ?** Je relis
    l'historique en base (500 dernières lignes), puis je compte en Python avec des
    dictionnaires et des boucles : une clé par niveau de risque, une par type, une
    par source, plus la moyenne des scores et un tri pour les sources les plus
    utilisées. Le tableau de bord est donc la preuve que la base de données sert
    à quelque chose.

---

## 5. Carte du code (pour retrouver une ligne vite)

```
app.py                  → routes Flask, enchaînement des 6 étapes, erreurs HTTP
  analyze()             → la fonction principale (celle à montrer d'abord)
  analyser_ioc()        → le moteur : enrichir, scorer, enregistrer
  analyser_lot()        → plusieurs IOC à la suite, avec budget de temps
  statistiques()        → tableau de bord (boucles + dictionnaires + tri)
  export_csv()          → export de l'historique au format CSV
  api_analyze()         → la même analyse, mais renvoyée en JSON
ioc_parser.py           → detect_type(), refang(), parse_ioc(), decoupe_iocs()
enrichment.py           → enrich() → enrich_ip() / enrich_domain() / enrich_hash()
  _get()                → l'appel HTTP centralisé et la gestion des erreurs réseau
  _email_security()     → SPF / DMARC / MX via Google DNS-over-HTTPS
scoring.py              → compute_risk() : signaux → score → niveau → réputation → action
db.py                   → save_analysis(), list_analyses(), find_last_analysis()
templates/index.html    → l'interface (formulaire, rapport, tableau de bord, historique)
api/index.py            → point d'entrée du déploiement Vercel
sql/schema.sql          → création de la table Supabase
tests/test_socle.py     → les 24 tests unitaires
tools/smoke_api.py      → test des API externes en vrai
```

---

**Dernier conseil.** Si tu ne comprends pas quelque chose, dis-le franchement et
lis la ligne concernée avant la soutenance : le code est entièrement commenté en
français, chaque fonction explique *pourquoi* elle existe. Une application simple
que tu maîtrises vaut plus qu'un projet complexe que tu subis.
