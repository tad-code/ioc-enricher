"""
Test « en conditions réelles » des trois API externes utilisées par le projet.

Ce script ne dépend pas de Flask : il vérifie simplement que chaque API répond,
que le JSON est exploitable et que le score de risque est calculé.

Lancement :
    python tools/smoke_api.py

Il nécessite un accès Internet.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scoring  # noqa: E402
from enrichment import EnrichmentError, enrich  # noqa: E402

CAS = [
    ("8.8.8.8", "ip"),
    ("185.220.101.1", "ip"),          # nœud de sortie Tor connu
    ("github.com", "domain"),
    ("ce-domaine-nexiste-pas-1234567890.com", "domain"),
    ("44d88612fea8a8f36de82e1278abb02f", "hash"),  # MD5 du fichier de test EICAR
    ("00000000000000000000000000000000", "hash"),  # empreinte inconnue
]

succes = 0
for ioc, type_attendu in CAS:
    try:
        resultat = enrich(ioc, type_attendu)
        risque = scoring.compute_risk(type_attendu, resultat)
        succes += 1
        print(f"[OK]   {ioc:<42} {resultat['source']:<20} HTTP {resultat['http_status']}  "
              f"-> {risque['reputation']} / {risque['level']} ({risque['score']}/100)")
        for raison in risque["reasons"][:3]:
            print(f"         · {raison}")
    except EnrichmentError as exc:
        print(f"[ECHEC] {ioc:<42} erreur {exc.kind} : {exc}")

print(f"\n{succes}/{len(CAS)} cas traités avec succès.")
sys.exit(0 if succes else 1)
