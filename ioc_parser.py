"""
Détection, normalisation et validation des IOC (Indicator Of Compromise).

Un IOC est un indice technique qui peut révéler une compromission :
adresse IP malveillante, nom de domaine suspect, empreinte (hash) de fichier.

Ce module est volontairement indépendant du réseau : il ne fait que du
traitement de chaînes de caractères, ce qui le rend facile à tester.
"""

from __future__ import annotations

import ipaddress
import re

# Un nom de domaine = au moins deux labels séparés par des points.
DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)"
    r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)

# Taille d'une empreinte -> algorithme correspondant.
HASH_ALGORITHMS = {32: "md5", 40: "sha1", 64: "sha256"}

# Une empreinte ne contient que des caractères hexadécimaux.
HEX_RE = re.compile(r"^[a-fA-F0-9]+$")

# Types d'IOC reconnus par l'application.
TYPES = {"ip": "Adresse IP", "domain": "Nom de domaine", "hash": "Empreinte de fichier"}


def refang(value: str) -> str:
    """Remet en forme un IOC « désamorcé » (defanged).

    Dans un rapport d'incident, les analystes neutralisent les liens pour
    éviter un clic accidentel :

        185[.]10[.]10[.]5   ->  185.10.10.5
        hxxps://evil[.]com  ->  https://evil.com
    """
    if not value:
        return ""
    result = value.strip()
    result = result.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    result = re.sub(r"^hxxp", "http", result, flags=re.IGNORECASE)
    # On retire la ponctuation typographique collée autour de l'IOC
    # (copier/coller depuis un email ou un rapport).
    return result.strip(" \t\r\n\"'<>|,;…")


SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)


def strip_scheme(value: str) -> str:
    """Retire un éventuel schéma d'URL (https://, ftp://...) pour ne garder
    que la donnée exploitable : l'hôte, l'adresse IP ou l'empreinte."""
    return SCHEME_RE.sub("", value or "")


def detect_type(value: str):
    """Devine le type d'un IOC : 'ip', 'domain', 'hash' ou None si inconnu."""
    candidate = strip_scheme(refang(value or ""))
    if not candidate:
        return None

    # 1) Une adresse IP (IPv4 ou IPv6) ?
    try:
        ipaddress.ip_address(candidate)
        return "ip"
    except ValueError:
        pass

    # 2) Une empreinte de fichier ? (hexadécimal de 32, 40 ou 64 caractères)
    if len(candidate) in HASH_ALGORITHMS and HEX_RE.match(candidate):
        return "hash"

    # 3) Un nom de domaine ? On tolère que l'analyste colle une URL complète.
    host = candidate.split("/")[0].split(":")[0]
    if DOMAIN_RE.match(host):
        return "domain"

    return None


def parse_ioc(value: str) -> dict:
    """Valide et normalise l'IOC saisi par l'utilisateur.

    Retourne toujours un dictionnaire de la forme :
        {
          "ok":     True / False,
          "error":  message d'erreur lisible ou None,
          "ioc":    IOC nettoyé,
          "type":   "ip" | "domain" | "hash" | None,
          "detail": précision utile (algorithme du hash, IP privée...)
        }
    """
    # --- Cas vide --------------------------------------------------------
    if value is None or not str(value).strip():
        return {
            "ok": False,
            "error": "Aucune valeur saisie : entrez une IP, un nom de domaine ou une empreinte de fichier.",
            "ioc": "",
            "type": None,
            "detail": None,
        }

    # --- Protection contre les saisies démesurées ------------------------
    # On borne la taille avant toute expression régulière : cela évite qu'une
    # chaîne très longue ne consomme inutilement du CPU.
    if len(value) > 512:
        return {
            "ok": False,
            "error": "Saisie trop longue : 512 caractères maximum.",
            "ioc": "",
            "type": None,
            "detail": None,
        }

    candidate = strip_scheme(refang(value))
    ioc_type = detect_type(candidate)

    # --- Cas invalide ----------------------------------------------------
    if ioc_type is None:
        return {
            "ok": False,
            "error": (
                f"« {candidate} » n'est pas un IOC valide. "
                "Formats acceptés : adresse IP, nom de domaine, ou hash MD5 / SHA1 / SHA256."
            ),
            "ioc": candidate,
            "type": None,
            "detail": None,
        }

    # --- Normalisation selon le type -------------------------------------
    detail = None

    if ioc_type == "ip":
        ip = ipaddress.ip_address(candidate)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            detail = (
                "Adresse privée / réservée (non routable sur Internet) : "
                "les bases publiques ne pourront rien dire d'utile sur elle."
            )
        candidate = str(ip)  # forme canonique (IPv6 compressée, etc.)

    elif ioc_type == "hash":
        candidate = candidate.lower()
        detail = f"Empreinte {HASH_ALGORITHMS[len(candidate)].upper()}"

    elif ioc_type == "domain":
        candidate = candidate.split("/")[0].split(":")[0].lower()
        if candidate.startswith("www.") and candidate.count(".") > 2:
            # www.evil.com et evil.com désignent le même domaine analysé.
            candidate = candidate[4:]

    return {"ok": True, "error": None, "ioc": candidate, "type": ioc_type, "detail": detail}
