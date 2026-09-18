"""
Moteur de scoring : transforme les signaux d'enrichissement en niveau de risque.

Principe : chaque source externe remonte dans `enrichment["signals"]` une liste
de dictionnaires {"points": int, "label": str}. Ce module additionne ces points,
ajoute quelques règles contextuelles (pays à risque, TLD suspect...) et
convertit le total en niveau lisible : LOW / MEDIUM / HIGH / CRITICAL.

Tout est transparent : le rapport affiche POURQUOI tel score a été attribué.
"""

from __future__ import annotations

# Score de départ : un IOC est par définition un élément à vérifier.
BASE_SCORE = 10

# Fourchettes -> niveau. On parcourt du plus élevé au plus faible.
LEVELS = ((75, "CRITICAL"), (50, "HIGH"), (25, "MEDIUM"), (0, "LOW"))

# Verdict de réputation associé au niveau : c'est la conclusion que l'analyste
# lit en premier (« ce domaine est-il fiable, oui ou non ? »).
REPUTATIONS = {
    "CRITICAL": "MALVEILLANT",
    "HIGH": "SUSPECT",
    "MEDIUM": "DOUTEUX",
    "LOW": "SAIN",
}

# Action à mener, déduite du niveau : c'est la décision que l'analyste attend.
ACTIONS = {
    "CRITICAL": "BLOQUER IMMÉDIATEMENT",
    "HIGH": "BLOQUER ET INVESTIGUER",
    "MEDIUM": "SURVEILLER",
    "LOW": "AUCUNE ACTION",
}

# Extension de domaine fréquemment détournée pour des campagnes malveillantes.
SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "gq", "cf", "ml", "work", "click",
    "country", "stream", "download", "rest", "fit", "buzz", "monster",
    "quest", "cfd", "sbs", "lol",
}

# Pays où l'hébergement d'infrastructures malveillantes est statistiquement
# sur-représenté dans les rapports publics de menace. Signal volontairement
# faible : un pays n'est jamais une preuve.
HIGH_ABUSE_COUNTRIES = {"RU", "CN", "IR", "KP", "NG", "VN", "BR", "IN", "UA"}


def level_for(score: int) -> str:
    """Convertit un score 0-100 en niveau de risque."""
    for seuil, niveau in LEVELS:
        if score >= seuil:
            return niveau
    return "LOW"


def reputation_for(level: str) -> str:
    """Traduit un niveau de risque en verdict de réputation lisible.

    Exemple : CRITICAL -> « MALVEILLANT », LOW -> « SAIN ».
    """
    return REPUTATIONS.get(level, "INCONNU")


def action_for(level: str) -> str:
    """Traduit un niveau de risque en action concrète pour l'analyste."""
    return ACTIONS.get(level, "À VÉRIFIER")


def _country_rule(enrichment: dict):
    """Règle contextuelle : localisation de l'infrastructure."""
    data = enrichment.get("data") or {}
    code = (data.get("country_code") or "").upper()
    pays = data.get("country") or "inconnu"
    if code in HIGH_ABUSE_COUNTRIES:
        return [{"points": 10, "label": f"Infrastructure localisée en {pays} ({code}), zone à forte activité malveillante rapportée"}]
    return []


def _tld_rule(ioc: str):
    """Règle contextuelle : extension de domaine à faible réputation."""
    if "." not in ioc:
        return []
    tld = ioc.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        return [{"points": 15, "label": f"Extension de domaine « .{tld} » très utilisée par les campagnes de phishing"}]
    return []


def compute_risk(ioc_type: str, enrichment: dict) -> dict:
    """Calcule le score (0-100), le niveau et la liste des raisons.

    Retourne {"score": int, "level": str, "reasons": [str, ...], "details": [...]}.
    """
    signaux = list(enrichment.get("signals") or [])

    # --- Cas particulier : adresse non routable (privée, locale, réservée) ---
    # Aucune base publique ne peut se prononcer : le score n'a pas de sens.
    # On l'annonce clairement au lieu d'afficher un faux « risque faible ».
    if enrichment.get("non_routable"):
        portee = enrichment.get("portee") or {}
        return {
            "score": 0,
            "level": "LOW",
            "reputation": "HORS PÉRIMÈTRE",
            "action": "AUCUNE ACTION — ADRESSE INTERNE",
            "reasons": [
                f"Adresse {portee.get('portee', 'non routable')} "
                f"({portee.get('plage', 'plage non routable')}) : "
                f"{portee.get('raison', 'cette adresse ne peut pas être interrogée sur Internet')}",
                "Aucune base de renseignement publique ne peut se prononcer sur "
                "une adresse qui n'est pas routable sur Internet",
                "Adresse interne au réseau : la vérification se fait dans "
                "l'inventaire du parc et les journaux, pas dans une API publique",
            ],
            "base_score": 0,
            "details": [],
        }

    # Règles contextuelles ajoutées par le moteur lui-même.
    # (La connaissance « fichier connu / inconnu » vient de l'API : elle est
    #  déjà comptée dans les signaux fournis par le module enrichment.)
    if ioc_type == "ip":
        signaux += _country_rule(enrichment)
    elif ioc_type == "domain":
        signaux += _tld_rule(enrichment.get("ioc", ""))

    total = BASE_SCORE + sum(int(s.get("points", 0)) for s in signaux)
    total = max(0, min(100, total))  # on borne le score entre 0 et 100

    raisons = [s["label"] for s in signaux] or [
        "Aucun signal négatif détecté par les sources interrogées"
    ]

    return {
        "score": total,
        "level": level_for(total),
        "reputation": reputation_for(level_for(total)),
        "action": action_for(level_for(total)),
        "reasons": raisons,
        "base_score": BASE_SCORE,
        "details": signaux,
    }
