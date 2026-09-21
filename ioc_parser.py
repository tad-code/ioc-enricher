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

# Un hôte suivi d'un numéro de port : « 8.8.8.8:8080 », « exemple.com:443 ».
# Le groupe « hote » interdit le deux-points, ce qui laisse les adresses IPv6
# intactes : leurs deux-points font partie de l'adresse, pas d'un port.
HOTE_PORT_RE = re.compile(r"^(?P<hote>[^\s:]+):(?P<port>\d{1,5})$")

# Une saisie qui a la forme d'une adresse IPv4 : quatre blocs numériques.
IPV4_FORME_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def strip_scheme(value: str) -> str:
    """Retire un éventuel schéma d'URL (https://, ftp://...) pour ne garder
    que la donnée exploitable : l'hôte, l'adresse IP ou l'empreinte."""
    return SCHEME_RE.sub("", value or "")


def retirer_port(value: str) -> str:
    """Retire un numéro de port collé à l'hôte : « 8.8.8.8:8080 » -> « 8.8.8.8 ».

    Pourquoi : un analyste copie très souvent une valeur « adresse:port » depuis
    un journal de connexion. Sans ce nettoyage, la chaîne n'est plus reconnue
    comme une adresse IP et retombe dans la détection de domaine, qui lui
    attribue alors un verdict faux (40/100 pour 8.8.8.8:8080).

    Les adresses IPv6 sont laissées telles quelles : leurs deux-points font
    partie de l'adresse elle-même, et non d'un port.
    """
    correspondance = HOTE_PORT_RE.match(value or "")
    if not correspondance:
        return value
    hote = correspondance.group("hote")
    # On n'agit que si ce qui précède ressemble à un hôte (il contient un point).
    if "." not in hote:
        return value
    return hote


def forme_ip_invalide(value: str):
    """Repère une adresse IPv4 mal formée, par exemple « 300.300.300.300 ».

    Pourquoi ce contrôle est indispensable : un nom de domaine peut légalement
    contenir des labels numériques, donc « 300.300.300.300 » satisfait
    l'expression régulière des domaines. Sans ce test, une adresse impossible
    était analysée comme un domaine suspect et recevait 55/100 — un contresens :
    elle n'existe pas, aucune base publique ne peut la connaître, et noter une
    faute de frappe revient à afficher un risque qui n'existe pas.

    Retourne un message d'erreur, ou None si la saisie n'a pas cette forme.
    """
    if not IPV4_FORME_RE.match(value or ""):
        return None
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return (
            f"« {value} » a la forme d'une adresse IP mais n'en est pas une : "
            "chaque bloc doit être compris entre 0 et 255."
        )
    return None


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


def portee_ip(value: str):
    """Indique si une adresse IP est routable sur Internet.

    Retourne None pour une adresse publique (donc analysable par les bases
    publiques), sinon un dictionnaire décrivant sa portée :

        {"portee": "privée", "plage": "192.168.0.0/16",
         "raison": "plage d'adressage privée (RFC 1918)"}

    Pourquoi ce contrôle existe : les API publiques de renseignement refusent
    ces adresses (ip-api.com répond « private range »). Sans ce test, l'outil
    afficherait une ERREUR alors que la bonne réponse est « cette adresse
    n'existe pas sur Internet, aucune base publique ne peut la connaître ».

    L'ordre des tests compte : en Python, une adresse de boucle locale
    (127.0.0.1) est aussi considérée comme privée — on veut donc la nommer
    précisément « locale » plutôt que « privée ».
    """
    try:
        adresse = ipaddress.ip_address(value)
    except ValueError:
        return None

    if adresse.is_unspecified:
        return {"portee": "non spécifiée", "plage": "0.0.0.0 ou ::",
                "raison": "adresse nulle : elle ne désigne aucun hôte"}
    if adresse.is_loopback:
        return {"portee": "locale", "plage": "127.0.0.0/8 ou ::1",
                "raison": "adresse de boucle locale : elle désigne la machine elle-même"}
    if adresse.is_link_local:
        return {"portee": "lien-local", "plage": "169.254.0.0/16 ou fe80::/10",
                "raison": "adresse auto-attribuée, valable uniquement sur le réseau local"}
    if adresse.is_private:
        return {"portee": "privée", "plage": "10.0.0.0/8, 172.16.0.0/12 ou 192.168.0.0/16",
                "raison": "plage d'adressage privée (RFC 1918)"}
    if adresse.is_multicast:
        return {"portee": "multicast", "plage": "224.0.0.0/4 ou ff00::/8",
                "raison": "adresse de diffusion de groupe, jamais attribuée à un hôte"}
    if adresse.is_reserved or not adresse.is_global:
        return {"portee": "réservée", "plage": "plage réservée par l'IANA",
                "raison": "plage réservée à un usage particulier, non routable"}
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

    candidate = retirer_port(strip_scheme(refang(value)))

    # --- Adresse IPv4 impossible -----------------------------------------
    # Un nom de domaine peut contenir des labels numériques : « 300.300.300.300 »
    # satisfait donc l'expression régulière des domaines. On refuse ce cas
    # explicitement, avant la détection de type, pour ne pas noter une faute de
    # frappe comme s'il s'agissait d'un domaine suspect.
    message_ip_invalide = forme_ip_invalide(candidate)
    if message_ip_invalide:
        return {
            "ok": False,
            "error": message_ip_invalide,
            "ioc": candidate,
            "type": None,
            "detail": None,
        }

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
        # « www. » est la sous-domaine la plus répandue du web et ne désigne pas
        # un domaine différent : www.github.com et github.com doivent donner le
        # même verdict. L'ancienne condition exigeait trois points ou plus, si
        # bien que www.github.com (deux points) n'était pas normalisé et
        # recevait 40/100 — un domaine inconnu du registre, disait l'analyse.
        if candidate.startswith("www.") and candidate.count(".") >= 2:
            candidate = candidate[4:]

    return {"ok": True, "error": None, "ioc": candidate, "type": ioc_type, "detail": detail}


def decoupe_iocs(texte: str, maximum: int = 5):
    """Découpe une saisie multiple en une liste d'IOC uniques.

    Séparateurs acceptés : retour à la ligne, virgule, point-virgule et
    tabulation — autrement dit « un indicateur par ligne », ce qui est la façon
    dont un analyste colle une liste. Les doublons sont supprimés et la liste
    est bornée pour ne pas dépasser le temps d'exécution autorisé côté
    hébergement.
    """
    morceaux = re.split(r"[\r\n,;\t]+", texte or "")
    uniques, vus = [], set()
    for morceau in morceaux:
        valeur = morceau.strip()
        if valeur and valeur.lower() not in vus:
            vus.add(valeur.lower())
            uniques.append(valeur)
    return uniques[:maximum]


def parse_many(texte: str, maximum: int = 5) -> dict:
    """Valide une liste d'IOC. Retourne les valides, les erreurs et le surplus.

    {
      "analyses": [ {résultat de parse_ioc}, ... ],   # IOC exploitables
      "erreurs":  [ {résultat de parse_ioc}, ... ],   # IOC refusés
      "ignorees": int,                                # au-delà du maximum
      "total":    int                                 # demandés au départ
    }
    """
    valeurs = decoupe_iocs(texte, maximum=10_000)
    total = len(valeurs)
    retenues = valeurs[:maximum]

    analyses, erreurs = [], []
    for valeur in retenues:
        resultat = parse_ioc(valeur)
        (analyses if resultat["ok"] else erreurs).append(resultat)

    return {
        "analyses": analyses,
        "erreurs": erreurs,
        "ignorees": max(0, total - len(retenues)),
        "total": total,
    }
