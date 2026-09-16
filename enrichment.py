"""
Interrogation des API externes d'enrichissement d'IOC.

Trois sources publiques sont utilisées, une par type d'IOC :

  * IP       -> ip-api.com          (géolocalisation + réseau, sans clé)
                AbuseIPDB           (réputation d'abus, avec clé API, prioritaire)
  * DOMAINE  -> rdap.org            (données d'enregistrement WHOIS/RDAP, sans clé)
                + résolution DNS     (l'API « DNS » du système)
  * HASH     -> hashlookup.circl.lu (base publique CIRCL, sans clé)

Chaque fonction retourne un dictionnaire normalisé que le gabarit HTML et le
moteur de score savent lire :

    {
      "source":       "ip-api.com",
      "endpoint":     "http://ip-api.com/json/8.8.8.8?fields=...",
      "http_status":  200,
      "raw":          { ... réponse JSON complète de l'API ... },
      "data":         { ... version normalisée (clés en snake_case) ... },
      "fields":       [("Pays", "United States"), ...],
      "signals":      [{"points": 25, "label": "..."}, ...],
      "notes":        ["..."]
    }
"""

from __future__ import annotations

import logging
import os
import socket

import requests

log = logging.getLogger("ioc-enricher.api")

TIMEOUT = 8  # secondes : on ne bloque pas l'utilisateur indéfiniment
HEADERS = {"User-Agent": "IOC-Enricher/1.0 (+https://github.com/tad-code/ioc-enricher)",
           "Accept": "application/json"}


class EnrichmentError(Exception):
    """Erreur d'enrichissement, avec une catégorie exploitable par l'interface.

    kind : "timeout" | "network" | "http" | "invalid" | "not_found" | "unknown"
    """

    def __init__(self, message: str, kind: str = "unknown"):
        super().__init__(message)
        self.kind = kind


def _get(url: str, *, headers: dict | None = None, params: dict | None = None) -> requests.Response:
    """Appel HTTP GET centralisé, avec gestion des erreurs réseau.

    Toutes les erreurs de bas niveau sont converties en EnrichmentError, ce qui
    évite de laisser remonter une trace Python jusqu'à l'utilisateur.
    """
    entetes = dict(HEADERS)
    if headers:
        entetes.update(headers)
    try:
        return requests.get(url, headers=entetes, params=params, timeout=TIMEOUT)
    except requests.Timeout as exc:
        raise EnrichmentError(
            f"L'API {url.split('/')[2]} n'a pas répondu en moins de {TIMEOUT} secondes.", kind="timeout"
        ) from exc
    except requests.ConnectionError as exc:
        raise EnrichmentError(
            "Connexion impossible à l'API externe (Internet indisponible ou DNS en panne).", kind="network"
        ) from exc
    except requests.RequestException as exc:  # filet de sécurité
        raise EnrichmentError(f"Erreur réseau inattendue : {exc}", kind="unknown") from exc


# ---------------------------------------------------------------------------
# 1) ENRICHISSEMENT DES ADRESSES IP
# ---------------------------------------------------------------------------

IP_API_FIELDS = (
    "status,message,continent,country,countryCode,regionName,city,zip,lat,lon,"
    "timezone,isp,org,as,reverse,mobile,proxy,hosting,query"
)


def _enrich_ip_with_abuseipdb(ip: str) -> dict:
    """AbuseIPDB : réputation d'abus d'une IP (nécessite une clé API gratuite)."""
    cle = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not cle:
        raise EnrichmentError("Clé ABUSEIPDB_API_KEY absente.", kind="invalid")

    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": "true"}
    reponse = _get(url, headers={"Key": cle, "Accept": "application/json"}, params=params)

    if reponse.status_code == 401:
        raise EnrichmentError("AbuseIPDB a refusé la clé API (401 Unauthorized).", kind="http")
    if reponse.status_code == 429:
        raise EnrichmentError("Quota AbuseIPDB dépassé (429 Too Many Requests).", kind="http")
    if reponse.status_code >= 400:
        raise EnrichmentError(f"AbuseIPDB a renvoyé le code HTTP {reponse.status_code}.", kind="http")

    brut = reponse.json()
    d = brut.get("data", {})
    confiance = int(d.get("abuseConfidenceScore") or 0)
    signaux = []
    if confiance >= 75:
        signaux.append({"points": 40, "label": f"Score d'abus AbuseIPDB très élevé ({confiance}/100)"})
    elif confiance >= 25:
        signaux.append({"points": 20, "label": f"Score d'abus AbuseIPDB modéré ({confiance}/100)"})
    if d.get("totalReports"):
        signaux.append({"points": min(20, int(d["totalReports"])), "label": f"{d['totalReports']} signalements d'abus recensés"})
    if d.get("isWhitelisted"):
        signaux.append({"points": -20, "label": "Adresse présente sur la liste blanche AbuseIPDB"})

    return {
        "source": "AbuseIPDB",
        "endpoint": f"{url}?ipAddress={ip}&maxAgeInDays=90",
        "http_status": reponse.status_code,
        "raw": brut,
        "data": {
            "country": d.get("countryCode"),
            "country_code": d.get("countryCode"),
            "isp": d.get("isp"),
            "domain": d.get("domain"),
            "usage_type": d.get("usageType"),
            "abuse_score": confiance,
            "total_reports": d.get("totalReports"),
            "is_tor": d.get("isTor"),
        },
        "fields": [
            ("Pays (code)", d.get("countryCode")),
            ("Fournisseur", d.get("isp")),
            ("Type d'usage", d.get("usageType")),
            ("Score d'abus", f"{confiance}/100"),
            ("Signalements", d.get("totalReports")),
            ("Nœud de sortie Tor", "oui" if d.get("isTor") else "non"),
        ],
        "signals": signaux,
        "notes": ["Source : AbuseIPDB (réputation communautaire)"],
    }


def _enrich_ip_with_ipapi(ip: str) -> dict:
    """ip-api.com : géolocalisation et informations réseau (sans clé API)."""
    url = f"http://ip-api.com/json/{ip}"
    reponse = _get(url, params={"fields": IP_API_FIELDS})

    if reponse.status_code == 429:
        raise EnrichmentError("Quota ip-api.com atteint (429 Too Many Requests, 45 requêtes/minute).", kind="http")
    if reponse.status_code >= 400:
        raise EnrichmentError(f"ip-api.com a renvoyé le code HTTP {reponse.status_code}.", kind="http")

    brut = reponse.json()

    # ip-api renvoie toujours 200, et signale l'échec DANS le JSON :
    # {"status":"fail","message":"private range", ...}
    if brut.get("status") != "success":
        message = brut.get("message", "réponse inexploitable")
        raise EnrichmentError(f"ip-api.com a refusé l'adresse {ip} : {message}.", kind="invalid")

    signaux = []
    if brut.get("hosting"):
        signaux.append({"points": 25, "label": "Adresse hébergée dans un datacenter / hébergeur (hosting)"})
    if brut.get("proxy"):
        signaux.append({"points": 35, "label": "Adresse détectée comme proxy / VPN / Tor"})
    if brut.get("mobile"):
        signaux.append({"points": 5, "label": "Adresse appartenant à un réseau mobile"})

    return {
        "source": "ip-api.com",
        "endpoint": f"{url}?fields={IP_API_FIELDS}",
        "http_status": reponse.status_code,
        "raw": brut,
        "data": {
            "country": brut.get("country"),
            "country_code": brut.get("countryCode"),
            "region": brut.get("regionName"),
            "city": brut.get("city"),
            "latitude": brut.get("lat"),
            "longitude": brut.get("lon"),
            "isp": brut.get("isp"),
            "org": brut.get("org"),
            "asn": brut.get("as"),
            "hosting": brut.get("hosting"),
            "proxy": brut.get("proxy"),
            "reverse_dns": brut.get("reverse"),
        },
        "fields": [
            ("Pays", f"{brut.get('country')} ({brut.get('countryCode')})"),
            ("Région", brut.get("regionName")),
            ("Ville", brut.get("city")),
            ("Coordonnées", f"{brut.get('lat')}, {brut.get('lon')}"),
            ("Fournisseur (ISP)", brut.get("isp")),
            ("Organisation", brut.get("org")),
            ("ASN / Réseau", brut.get("as")),
            ("DNS inverse", brut.get("reverse") or "-"),
            ("Datacenter", "oui" if brut.get("hosting") else "non"),
            ("Proxy / VPN", "oui" if brut.get("proxy") else "non"),
        ],
        "signals": signaux,
        "notes": ["Source : ip-api.com (géolocalisation IP, sans clé API)"],
    }


def enrich_ip(ip: str) -> dict:
    """Enrichit une IP : AbuseIPDB si une clé existe, sinon ip-api.com en secours."""
    if os.getenv("ABUSEIPDB_API_KEY", "").strip():
        try:
            return _enrich_ip_with_abuseipdb(ip)
        except EnrichmentError as exc:
            log.warning("AbuseIPDB indisponible (%s), repli sur ip-api.com", exc)
            resultat = _enrich_ip_with_ipapi(ip)
            resultat["notes"].append(f"AbuseIPDB indisponible ({exc.kind}) : repli sur ip-api.com")
            return resultat
    return _enrich_ip_with_ipapi(ip)


# ---------------------------------------------------------------------------
# 2) ENRICHISSEMENT DES NOMS DE DOMAINE
# ---------------------------------------------------------------------------


def _resolve_domain(domain: str):
    """Résolution DNS locale : le domaine existe-t-il vraiment ?"""
    try:
        return {"a_record": socket.gethostbyname(domain), "resolved": True}
    except socket.gaierror:
        return {"a_record": None, "resolved": False}


def _age_in_days(date_creation: str | None):
    """Âge d'un domaine en jours à partir d'une date ISO RDAP."""
    if not date_creation:
        return None
    from datetime import datetime, timezone

    try:
        brut = date_creation.replace("Z", "+00:00")
        creation = datetime.fromisoformat(brut)
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - creation).days
    except ValueError:
        return None


def enrich_domain(domain: str) -> dict:
    """Enrichit un domaine : données RDAP (enregistrement) + résolution DNS."""
    url = f"https://rdap.org/domain/{domain}"
    dns = _resolve_domain(domain)
    signaux = []

    if not dns["resolved"]:
        signaux.append({"points": 15, "label": "Le domaine ne se résout pas en adresse IP (aucun enregistrement A)"})

    reponse = _get(url)
    statut = reponse.status_code

    # 404 = le domaine n'est pas enregistré (ou supprimé) : signal fort.
    if statut == 404:
        signaux.append({"points": 30, "label": "Domaine inconnu du registre (RDAP 404) : non enregistré ou expiré"})
        return {
            "source": "RDAP (rdap.org)",
            "endpoint": url,
            "http_status": statut,
            "raw": {"errorCode": 404, "title": "Not Found"},
            "data": {"domain": domain, "registered": False, **dns},
            "fields": [
                ("Domaine", domain),
                ("Enregistré", "non (404)"),
                ("Adresse IP", dns["a_record"] or "-"),
            ],
            "signals": signaux,
            "notes": ["RDAP ne connaît pas ce domaine : il n'est pas (ou plus) enregistré."],
        }

    if statut >= 400:
        raise EnrichmentError(f"Le service RDAP a renvoyé le code HTTP {statut}.", kind="http")

    brut = reponse.json()

    # --- Événements (création / expiration / mise à jour) ----------------
    evenements = {e.get("eventAction"): e.get("eventDate") for e in brut.get("events", [])}
    creation = evenements.get("registration")
    expiration = evenements.get("expiration")
    age = _age_in_days(creation)

    # --- Registrar --------------------------------------------------------
    registrar = None
    for entite in brut.get("entities", []):
        if "registrar" in (entite.get("roles") or []):
            for vcard in entite.get("vcardArray", [[], []])[1]:
                if vcard[0] == "fn":
                    registrar = vcard[3]
                    break
            break

    # --- Serveurs de noms -------------------------------------------------
    nameservers = ", ".join(ns.get("ldhName", "").lower() for ns in brut.get("nameservers", []) if ns.get("ldhName")) or None

    # --- Règles de risque liées à l'âge ----------------------------------
    if age is not None:
        if age < 30:
            signaux.append({"points": 30, "label": f"Domaine enregistré récemment ({age} jours)"})
        elif age < 180:
            signaux.append({"points": 15, "label": f"Domaine récent ({age} jours)"})
        else:
            signaux.append({"points": -10, "label": f"Domaine ancien ({age} jours) : ancienneté rassurante"})

    statuts = ", ".join(brut.get("status", [])) or "-"
    if "client hold" in statuts or "server hold" in statuts:
        signaux.append({"points": 35, "label": "Domaine suspendu par le registre (client hold / server hold)"})

    if len(brut.get("nameservers", [])) <= 1:
        signaux.append({"points": 5, "label": "Un seul serveur de noms déclaré"})

    return {
        "source": "RDAP (rdap.org)",
        "endpoint": url,
        "http_status": statut,
        "raw": brut,
        "data": {
            "domain": domain,
            "registered": True,
            "registrar": registrar,
            "created_at": creation,
            "expires_at": expiration,
            "age_days": age,
            "nameservers": nameservers,
            "status": statuts,
            "a_record": dns["a_record"],
            "resolved": dns["resolved"],
        },
        "fields": [
            ("Domaine", domain),
            ("Registrar", registrar or "non communiqué"),
            ("Créé le", creation or "-"),
            ("Expire le", expiration or "-"),
            ("Âge", f"{age} jours" if age is not None else "-"),
            ("Serveurs de noms", nameservers or "-"),
            ("Statut registre", statuts),
            ("Adresse IP", dns["a_record"] or "aucune"),
        ],
        "signals": signaux,
        "notes": ["Source : RDAP via rdap.org (données d'enregistrement publiques)"],
    }


# ---------------------------------------------------------------------------
# 3) ENRICHISSEMENT DES EMPREINTES (HASH)
# ---------------------------------------------------------------------------

HASHLOOKUP_ENDPOINTS = {
    32: "https://hashlookup.circl.lu/lookup/md5/",
    40: "https://hashlookup.circl.lu/lookup/sha1/",
    64: "https://hashlookup.circl.lu/lookup/sha256/",
}


def enrich_hash(empreinte: str) -> dict:
    """Enrichit un hash via hashlookup.circl.lu (base publique CIRCL, sans clé)."""
    url = HASHLOOKUP_ENDPOINTS[len(empreinte)] + empreinte
    signaux = []
    reponse = _get(url)
    statut = reponse.status_code

    if statut == 404:
        signaux.append({"points": 10, "label": "Empreinte inconnue de la base publique (fichier jamais catalogué)"})
        return {
            "source": "CIRCL hashlookup",
            "endpoint": url,
            "http_status": statut,
            "raw": {"error": "not found"},
            "data": {"hash": empreinte, "known": False},
            "fields": [
                ("Empreinte", empreinte),
                ("Algorithme", {32: "MD5", 40: "SHA-1", 64: "SHA-256"}[len(empreinte)]),
                ("Connue des bases publiques", "non"),
            ],
            "signals": signaux,
            "notes": ["L'empreinte n'est pas référencée : le fichier n'a pas été catalogué par CIRCL."],
        }

    if statut >= 400:
        raise EnrichmentError(f"hashlookup.circl.lu a renvoyé le code HTTP {statut}.", kind="http")

    brut = reponse.json()
    confiance = brut.get("hashlookup:trust")
    if isinstance(confiance, int):
        if confiance >= 80:
            signaux.append({"points": -10, "label": f"Fichier connu et fiable (indice de confiance {confiance}/100)"})
        elif confiance < 50:
            signaux.append({"points": 30, "label": f"Fichier connu mais peu fiable (indice de confiance {confiance}/100)"})

    return {
        "source": "CIRCL hashlookup",
        "endpoint": url,
        "http_status": statut,
        "raw": brut,
        "data": {
            "hash": empreinte,
            "known": True,
            "file_name": brut.get("FileName"),
            "file_size": brut.get("FileSize"),
            "product": brut.get("ProductName"),
            "publisher": brut.get("Publisher"),
            "trust": confiance,
        },
        "fields": [
            ("Empreinte", empreinte),
            ("Algorithme", {32: "MD5", 40: "SHA-1", 64: "SHA-256"}[len(empreinte)]),
            ("Nom du fichier", brut.get("FileName") or "-"),
            ("Taille", f"{brut.get('FileSize')} octets" if brut.get("FileSize") else "-"),
            ("Produit", brut.get("ProductName") or "-"),
            ("Éditeur", brut.get("Publisher") or "-"),
            ("Indice de confiance", f"{confiance}/100" if confiance is not None else "-"),
        ],
        "signals": signaux,
        "notes": ["Source : hashlookup.circl.lu (équipe CIRCL, Luxembourg)"],
    }


# ---------------------------------------------------------------------------
# POINT D'ENTRÉE UNIQUE
# ---------------------------------------------------------------------------

def enrich(ioc: str, ioc_type: str) -> dict:
    """Appelle la bonne API selon le type d'IOC détecté."""
    repartition = {"ip": enrich_ip, "domain": enrich_domain, "hash": enrich_hash}
    if ioc_type not in repartition:
        raise EnrichmentError(f"Type d'IOC non pris en charge : {ioc_type}", kind="invalid")

    resultat = repartition[ioc_type](ioc)
    resultat["ioc"] = ioc
    resultat["ioc_type"] = ioc_type
    return resultat
