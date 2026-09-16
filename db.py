"""
Couche d'accès à la base de données Supabase.

Supabase expose chaque table PostgreSQL à travers une API REST (PostgREST) :

    POST   https://<projet>.supabase.co/rest/v1/ioc_analyses
    apikey: <clé anon>
    Authorization: Bearer <clé anon>
    Content-Type: application/json

Toutes les opérations sont donc de simples requêtes HTTP + JSON, ce qui rend
le fonctionnement explicite et facile à expliquer en soutenance.
"""

from __future__ import annotations

import logging
import os

import requests

log = logging.getLogger("ioc-enricher.db")

TIMEOUT = 10          # secondes
TABLE = "ioc_analyses"  # table créée par sql/schema.sql


class DatabaseError(Exception):
    """Erreur de communication avec Supabase.

    kind : "not_configured" | "timeout" | "network" | "http"
    """

    def __init__(self, message: str, kind: str = "unknown"):
        super().__init__(message)
        self.kind = kind


def _cle() -> str:
    """Clé à utiliser pour parler à la base.

    Priorité à SUPABASE_SECRET_KEY : cette clé secrète reste **côté serveur**,
    elle n'est jamais envoyée au navigateur et contourne les règles RLS.
    SUPABASE_ANON_KEY n'est utilisée qu'en secours (mode dégradé).
    """
    return (
        os.getenv("SUPABASE_SECRET_KEY", "").strip()
        or os.getenv("SUPABASE_ANON_KEY", "").strip()
    )


def is_configured() -> bool:
    """L'application a-t-elle de quoi parler à la base ?"""
    return bool(os.getenv("SUPABASE_URL", "").strip()) and bool(_cle())


def uses_secret_key() -> bool:
    """La configuration utilise-t-elle la clé secrète (mode recommandé) ?"""
    return bool(os.getenv("SUPABASE_SECRET_KEY", "").strip())


def _headers(extra: dict | None = None) -> dict:
    cle = _cle()
    entetes = {
        "apikey": cle,
        "Authorization": f"Bearer {cle}",
        "Content-Type": "application/json",
    }
    if extra:
        entetes.update(extra)
    return entetes


def _endpoint() -> str:
    return os.getenv("SUPABASE_URL", "").rstrip("/") + f"/rest/v1/{TABLE}"


def _call(method: str, *, params=None, payload=None, extra_headers=None) -> requests.Response:
    """Exécute une requête HTTP vers Supabase en traduisant les erreurs."""
    if not is_configured():
        raise DatabaseError(
            "Base de données non configurée : renseignez SUPABASE_URL et "
            "SUPABASE_SECRET_KEY (ou SUPABASE_ANON_KEY) dans le fichier .env.",
            kind="not_configured",
        )
    try:
        reponse = requests.request(
            method,
            _endpoint(),
            params=params,
            json=payload,
            headers=_headers(extra_headers),
            timeout=TIMEOUT,
        )
    except requests.Timeout as exc:
        raise DatabaseError("Supabase n'a pas répondu dans le délai imparti.", kind="timeout") from exc
    except requests.ConnectionError as exc:
        raise DatabaseError("Connexion à Supabase impossible (réseau ou DNS indisponible).", kind="network") from exc

    if reponse.status_code >= 400:
        raise DatabaseError(
            f"Supabase a renvoyé le code HTTP {reponse.status_code} : {reponse.text[:200]}",
            kind="http",
        )
    return reponse


def save_analysis(*, ioc, ioc_type, risk_level, risk_score, source_api, summary, reasons) -> dict:
    """Enregistre une analyse et retourne la ligne créée (avec son id et sa date)."""
    ligne = {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "risk_level": risk_level,
        "risk_score": int(risk_score),
        "source_api": source_api,
        "summary": summary,      # objet JSON stocké dans une colonne jsonb
        "reasons": reasons,      # tableau JSON
    }
    # Prefer: return=representation -> PostgREST renvoie la ligne insérée.
    reponse = _call("POST", payload=ligne, extra_headers={"Prefer": "return=representation"})
    try:
        donnees = reponse.json()
    except ValueError:
        return {}
    if isinstance(donnees, list) and donnees:
        return donnees[0]
    return {}


def list_analyses(limit: int = 25):
    """Retourne (lignes, message_erreur). L'erreur est affichée sans casser la page."""
    try:
        reponse = _call("GET", params={"select": "*", "order": "created_at.desc", "limit": limit})
        donnees = reponse.json()
        return (donnees if isinstance(donnees, list) else []), None
    except DatabaseError as exc:
        log.warning("Lecture de l'historique impossible : %s", exc)
        return [], str(exc)
    except ValueError:
        return [], "Réponse illisible de Supabase (JSON invalide)."


def delete_analysis(row_id: int) -> bool:
    """Supprime une analyse par son identifiant. Lève DatabaseError en cas d'échec."""
    _call("DELETE", params={"id": f"eq.{int(row_id)}"})
    return True


def find_last_analysis(ioc: str):
    """Retourne la dernière analyse connue pour cet IOC, ou None.

    Sert à repérer les indicateurs « déjà vus » : un analyste doit savoir que
    le même IOC a déjà été qualifié, et comparer les deux scores.
    """
    try:
        reponse = _call("GET", params={
            "select": "id,ioc,risk_level,risk_score,created_at,summary",
            "ioc": f"eq.{ioc}",
            "order": "created_at.desc",
            "limit": 1,
        })
        donnees = reponse.json()
        if isinstance(donnees, list) and donnees:
            return donnees[0]
    except (DatabaseError, ValueError):
        pass
    return None


def list_analyses_large(limit: int = 500):
    """Historique élargi, utilisé pour calculer les statistiques."""
    try:
        reponse = _call("GET", params={
            "select": "id,ioc,ioc_type,risk_level,risk_score,source_api,summary,created_at",
            "order": "created_at.desc",
            "limit": limit,
        })
        donnees = reponse.json()
        return (donnees if isinstance(donnees, list) else []), None
    except DatabaseError as exc:
        log.warning("Lecture étendue impossible : %s", exc)
        return [], str(exc)
    except ValueError:
        return [], "Réponse illisible de la base de données (JSON invalide)."


def count_analyses() -> int:
    """Nombre total d'analyses enregistrées (utilise l'en-tête Content-Range)."""
    try:
        reponse = _call("GET", params={"select": "id"}, extra_headers={"Prefer": "count=exact", "Range": "0-0"})
        portee = reponse.headers.get("Content-Range", "")  # ex. "0-0/42"
        if "/" in portee:
            return int(portee.split("/")[-1])
    except (DatabaseError, ValueError):
        pass
    return 0
