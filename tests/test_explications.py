"""
Tests des explications.

L'engagement pris envers l'utilisateur est le suivant : **aucun élément affiché
sans explication**. Un tel engagement ne tient que s'il est vérifié
automatiquement, autrement la première source ajoutée le rompt en silence.

Ces tests parcourent donc réellement tous les chemins d'enrichissement, avec des
réponses simulées, et vérifient que chaque champ et chaque signal rencontrés
trouvent bien leur explication.
"""
from __future__ import annotations

import json
import re
import sys
import os
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import enrichment  # noqa: E402
import explications  # noqa: E402
import scoring  # noqa: E402

SENTENCE_DE_REPLI = "Aucune explication rédigée"


# ---------------------------------------------------------------------------
# Réponses simulées pour chaque source
# ---------------------------------------------------------------------------

PAYLOAD_IPAPI = {
    "status": "success", "country": "Allemagne", "countryCode": "DE", "regionName": "Hesse",
    "city": "Francfort", "lat": 50.1169, "lon": 8.6837, "isp": "Cloudflare, Inc.",
    "org": "DET FRA", "as": "AS13335 Cloudflare, Inc.", "reverse": "p.l5e.io",
    "mobile": False, "proxy": False, "hosting": True, "query": "185.158.133.1",
}

PAYLOAD_IPAPI_SUSPECT = dict(PAYLOAD_IPAPI, country="Russie", countryCode="RU",
                             isp="Hébergeur inconnu", proxy=True, mobile=True)

PAYLOAD_ABUSEIPDB = {
    "data": {
        "countryCode": "DE", "isp": "Cloudflare", "domain": "cloudflare.com",
        "usageType": "Data Center/Web Hosting/Transit", "abuseConfidenceScore": 100,
        "totalReports": 42, "isTor": True, "isWhitelisted": False,
    }
}

PAYLOAD_RDAP = {
    "ldhName": "EXEMPLE.COM",
    "events": [
        {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
    ],
    "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "OVH SAS"]]]}],
    "nameservers": [{"ldhName": "NS1.EXEMPLE.COM"}, {"ldhName": "NS2.EXEMPLE.COM"}],
    "status": ["client transfer prohibited"],
}

PAYLOAD_RDAP_JEUNE = dict(
    PAYLOAD_RDAP,
    events=[{"eventAction": "registration", "eventDate": "2026-09-15T00:00:00Z"}],
    nameservers=[{"ldhName": "NS1.EXEMPLE.COM"}],
    status=["client hold"],
)

PAYLOAD_HASH = {
    "FileName": "programme.exe", "FileSize": 204800, "ProductName": "Produit connu",
    "Publisher": "Éditeur connu", "hashlookup:trust": 80,
}

PAYLOAD_HASH_PEU_FIABLE = dict(PAYLOAD_HASH, **{"hashlookup:trust": 20})


class FauxReponse:
    """Réponse HTTP simulée, avec le strict nécessaire."""

    def __init__(self, payload, code=200):
        self._payload = payload
        self.status_code = code
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


def fabriquer_faux_get(*, ipapi=None, hashlookup=None, rdap=None, rdap_absent=False, dns_ok=True):
    """Construit une fonction remplaçant l'appel HTTP réel de l'enrichissement."""

    def faux_get(url, headers=None, params=None):
        params = params or {}
        if "ip-api.com" in url:
            return FauxReponse(ipapi if ipapi is not None else PAYLOAD_IPAPI)
        if "abuseipdb.com" in url:
            return FauxReponse(PAYLOAD_ABUSEIPDB)
        if "rdap.org" in url:
            if rdap_absent:
                return FauxReponse({"errorCode": 404}, 404)
            return FauxReponse(rdap if rdap is not None else PAYLOAD_RDAP)
        if "hashlookup.circl.lu" in url:
            if hashlookup is None:
                return FauxReponse({"error": "not found"}, 404)
            return FauxReponse(hashlookup)
        if "dns.google" in url:
            if not dns_ok:
                return FauxReponse({})
            nom = params.get("name", "")
            type_ = params.get("type", "")
            if type_ == "MX":
                return FauxReponse({"Answer": [{"data": "10 mail.exemple.com."}]})
            if nom.startswith("_dmarc."):
                return FauxReponse({"Answer": [{"data": "v=DMARC1; p=reject"}]})
            return FauxReponse({"Answer": [{"data": "v=spf1 include:_spf.exemple.com -all"}]})
        return FauxReponse({}, 404)

    return faux_get


def preparer(monkeypatch, **options):
    """Remplace les appels sortants et la résolution DNS locale."""
    monkeypatch.setattr(enrichment, "_get", fabriquer_faux_get(**options))
    monkeypatch.setattr(
        enrichment, "_resolve_domain", lambda domaine: {"a_record": "93.184.216.34", "resolved": True}
    )


# ---------------------------------------------------------------------------
# 1) Couverture : chaque champ affiché possède une explication
# ---------------------------------------------------------------------------

CAS_CHAMPS = [
    ("8.8.8.8", "ip"),
    ("185.158.133.1", "ip"),
    ("192.168.1.1", "ip"),
    ("127.0.0.1", "ip"),
    ("fe80::1", "ip"),
    ("exemple.com", "domain"),
    ("a" * 32, "hash"),
    ("b" * 40, "hash"),
    ("c" * 64, "hash"),
]


def test_chaque_champ_produit_par_le_code_est_explique(monkeypatch):
    """Parcours de tous les chemins d'enrichissement, sources simulées."""
    preparer(monkeypatch)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)

    sans_explication = []
    for ioc, type_ioc in CAS_CHAMPS:
        resultat = enrichment.enrich(ioc, type_ioc)
        for champ in resultat["fields"]:
            if SENTENCE_DE_REPLI in champ["explication"]:
                sans_explication.append(f"{ioc} -> {champ['libelle']}")

    assert sans_explication == [], f"Champs sans explication : {sans_explication}"


def test_chaque_champ_est_explique_avec_la_source_de_reputation(monkeypatch):
    """Second chemin possible pour une IP : AbuseIPDB, quand une clé est fournie."""
    preparer(monkeypatch)
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "cle-de-test")

    resultat = enrichment.enrich("8.8.8.8", "ip")
    sans_explication = [
        champ["libelle"]
        for champ in resultat["fields"]
        if SENTENCE_DE_REPLI in champ["explication"]
    ]
    assert sans_explication == [], f"Champs sans explication : {sans_explication}"


def test_chaque_champ_de_la_voie_non_routable_est_explique(monkeypatch):
    preparer(monkeypatch)
    resultat = enrichment.enrich("10.0.0.1", "ip")
    sans_explication = [
        champ["libelle"] for champ in resultat["fields"] if SENTENCE_DE_REPLI in champ["explication"]
    ]
    assert sans_explication == [], f"Champs sans explication : {sans_explication}"


def test_chaque_champ_d_un_domaine_non_enregistre_est_explique(monkeypatch):
    """Chemin particulier : le registre ne connaît pas le domaine.

    Il produit une liste de champs plus courte que le cas nominal, avec une clé
    qui n'existe nulle part ailleurs. Sans ce test, ce chemin échapperait à la
    vérification — c'est exactement ce qui s'est produit à la première écriture.
    """
    preparer(monkeypatch, rdap_absent=True)
    resultat = enrichment.enrich("domaine-inexistant.xyz", "domain")

    assert resultat["fields"], "Ce chemin doit tout de même renvoyer des informations"
    sans_explication = [
        champ["libelle"] for champ in resultat["fields"] if SENTENCE_DE_REPLI in champ["explication"]
    ]
    assert sans_explication == [], f"Champs sans explication : {sans_explication}"


# ---------------------------------------------------------------------------
# 2) Couverture : chaque signal qui pèse dans le score possède une explication
# ---------------------------------------------------------------------------

CAS_SIGNAUX = [
    ("8.8.8.8", "ip", {}),                                        # source de réputation standard
    ("185.158.133.1", "ip", {"ipapi": PAYLOAD_IPAPI_SUSPECT}),     # pays, proxy, mobile
    ("exemple.com", "domain", {}),                                 # domaine ordinaire
    ("exemple.com", "domain", {"rdap": PAYLOAD_RDAP_JEUNE, "dns_ok": False}),  # jeune, suspendu
    ("promo-cadeau.xyz", "domain", {}),                            # extension suspecte
    ("a" * 32, "hash", {}),                                        # empreinte inconnue
    ("a" * 32, "hash", {"hashlookup": PAYLOAD_HASH}),              # fichier fiable
    ("a" * 32, "hash", {"hashlookup": PAYLOAD_HASH_PEU_FIABLE}),   # fichier peu fiable
]


def test_chaque_signal_du_score_est_explique(monkeypatch):
    sans_explication = []
    for ioc, type_ioc, options in CAS_SIGNAUX:
        preparer(monkeypatch, **options)
        monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
        enrichissement = enrichment.enrich(ioc, type_ioc)
        risque = scoring.compute_risk(type_ioc, enrichissement)
        for detail in risque["details"]:
            if SENTENCE_DE_REPLI in detail["explication"]:
                sans_explication.append(f"{ioc} -> {detail['label']}")

    assert sans_explication == [], f"Signaux sans explication : {sans_explication}"


def test_les_raisons_d_un_hors_perimetre_sont_expliquees(monkeypatch):
    preparer(monkeypatch)
    enrichissement = enrichment.enrich("192.168.1.1", "ip")
    risque = scoring.compute_risk("ip", enrichissement)

    assert risque["details"], "Un hors-périmètre doit tout de même expliquer ses raisons"
    for detail in risque["details"]:
        assert SENTENCE_DE_REPLI not in detail["explication"]
        assert detail["points"] == 0, "Aucun point ne doit être attribué hors périmètre"


def test_l_absence_de_signal_est_expliquee(monkeypatch):
    """« 10/100 » sans un mot laisserait l'analyste devant un chiffre muet."""
    preparer(monkeypatch)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    enrichissement = enrichment.enrich("8.8.8.8", "ip")
    risque = scoring.compute_risk("ip", enrichissement)

    if risque["score"] == scoring.BASE_SCORE:
        assert risque["details"]
        assert SENTENCE_DE_REPLI not in risque["details"][0]["explication"]


# ---------------------------------------------------------------------------
# 3) Qualité des explications rédigées
# ---------------------------------------------------------------------------

def test_un_champ_inconnu_signale_son_absence_d_explication():
    """Le repli doit être visible, jamais silencieux."""
    resultat = explications.expliquer_champs([("Champ inventé", "valeur")])
    assert SENTENCE_DE_REPLI in resultat[0]["explication"]


def test_expliquer_champs_conserve_le_libelle_et_la_valeur():
    resultat = explications.expliquer_champs([("Pays", "Allemagne")])
    assert resultat[0]["libelle"] == "Pays"
    assert resultat[0]["valeur"] == "Allemagne"
    assert resultat[0]["explication"]
    assert resultat[0]["pourquoi"]


def test_explication_signal_tolere_une_valeur_en_debut_de_libelle():
    """Les libellés commencent parfois par un nombre : la recherche doit suivre."""
    trouve = explications.explication_signal("42 signalements d'abus recensés")
    assert trouve is not None
    assert trouve["explication"]


def test_explication_signal_inconnu_renvoie_none():
    assert explications.explication_signal("Signal qui n'existe pas") is None


def test_les_explications_des_champs_sont_toutes_redigees():
    """Aucune entrée de la table ne doit être vide ou bâclée."""
    for libelle, contenu in explications.CHAMPS.items():
        assert len(contenu["explication"]) > 40, f"Explication trop courte : {libelle}"
        assert len(contenu["pourquoi"]) > 30, f"Justification trop courte : {libelle}"


def test_les_explications_des_signaux_sont_toutes_redigees():
    for fragment, explication, pourquoi in explications.SIGNAUX:
        assert len(explication) > 40, f"Explication trop courte : {fragment}"
        assert len(pourquoi) > 30, f"Justification trop courte : {fragment}"


# ---------------------------------------------------------------------------
# 4) Le glossaire
# ---------------------------------------------------------------------------

def test_le_glossaire_est_regroupe_par_categorie():
    categories = explications.glossaire()
    assert len(categories) >= 5
    for bloc in categories:
        assert bloc["categorie"]
        assert bloc["concepts"]
        termes = [c["terme"] for c in bloc["concepts"]]
        assert termes == sorted(termes, key=str.lower), f"Tri absent dans {bloc['categorie']}"


def test_chaque_concept_du_glossaire_est_redige():
    for concept in explications.CONCEPTS:
        assert len(concept["explication"]) > 40, concept["terme"]
        assert len(concept["en_pratique"]) > 40, concept["terme"]


def test_aucun_terme_de_glossaire_n_est_en_double():
    termes = [c["terme"] for c in explications.CONCEPTS]
    assert len(termes) == len(set(termes))


def test_le_compte_des_explications_est_coherent():
    compte = explications.nombre_explications()
    assert compte["champs"] == len(explications.CHAMPS)
    assert compte["signaux"] == len(explications.SIGNAUX)
    assert compte["concepts"] == len(explications.CONCEPTS)
    assert compte["concepts"] >= 25


# ---------------------------------------------------------------------------
# 5) Contrôles statiques
#
# Le parcours dynamique ne vérifie que les chemins qu'il exerce. Un champ ou un
# signal ajouté demain au code, sans explication, passerait donc inaperçu. Ces
# deux contrôles lisent la source du module et comblent cette faille : ils ne
# dépendent pas des cas de test.
# ---------------------------------------------------------------------------

RACINE = Path(__file__).resolve().parent.parent


def test_tous_les_champs_declares_dans_le_code_sont_couverts():
    source = (RACINE / "enrichment.py").read_text(encoding="utf-8")
    blocs = re.findall(r'"fields":\s*\[(.*?)\n\s*\]', source, re.S)

    libelles: set[str] = set()
    for bloc in blocs:
        # Un libellé de champ commence sa ligne par une parenthèse ouvrante.
        libelles.update(re.findall(r'^\s*\("([^"]+)"\s*,', bloc, re.M))

    assert len(libelles) >= 35, f"Extraction suspecte : {len(libelles)} libellés trouvés"
    manquants = sorted(libelle for libelle in libelles if libelle not in explications.CHAMPS)
    assert manquants == [], f"Champs du code sans explication : {manquants}"


def test_tous_les_signaux_declares_dans_le_code_sont_couverts():
    fragments = []
    for nom_fichier in ("enrichment.py", "scoring.py"):
        source = (RACINE / nom_fichier).read_text(encoding="utf-8")
        for brut in re.findall(r'"label":\s*f?"([^"]+)"', source):
            # On retire les valeurs interpolées : elles changent à l'exécution.
            propre = re.sub(r"\{[^}]*\}", "", brut).strip()
            if len(propre) >= 15:  # écarte les exemples abrégés des commentaires
                fragments.append((nom_fichier, propre))

    assert len(fragments) >= 20, f"Extraction suspecte : {len(fragments)} signaux trouvés"
    manquants = [
        (fichier, texte)
        for fichier, texte in fragments
        if explications.explication_signal(texte) is None
    ]
    assert manquants == [], f"Signaux du code sans explication : {manquants}"


# ---------------------------------------------------------------------------
# 6) Rendu final : la page ne doit contenir aucun trou
#
# Les contrôles ci-dessus portent sur les données. Ceux-ci portent sur ce que le
# visiteur reçoit réellement. Une adresse non routable suffit : elle est analysée
# localement, donc le test ne dépend d'aucun réseau ni d'aucune base de données.
# ---------------------------------------------------------------------------

ADRESSE_LOCALE = "192.168.1.1"


def test_la_page_de_glossaire_est_servie_et_complete():
    from app import app

    page = app.test_client().get("/glossaire")
    assert page.status_code == 200
    corps = page.get_data(as_text=True)

    for terme_attendu in ("ASN", "RDAP", "DMARC", "Tor", "Faux positif", "Adresse privée",
                          "IOC désamorcé", "Leetspeak"):
        assert terme_attendu in corps, f"Terme absent du glossaire : {terme_attendu}"
    assert "Aucune explication rédigée" not in corps


def test_le_rapport_affiche_explique_chaque_element():
    from app import app

    page = app.test_client().post("/analyze", data={"ioc": ADRESSE_LOCALE})
    assert page.status_code == 200
    corps = page.get_data(as_text=True)

    assert 'class="explique"' in corps, "Les signaux du score doivent être expliqués"
    assert 'class="champ-explique"' in corps, "Les informations doivent être expliquées"
    # L'engagement central : rien ne s'affiche sans explication rédigée.
    assert "Aucune explication rédigée" not in corps


def test_l_api_restitue_les_explications():
    from app import app

    reponse = app.test_client().get(f"/api/analyze?ioc={ADRESSE_LOCALE}&save=0")
    assert reponse.status_code == 200
    donnees = reponse.get_json()

    assert donnees["informations"], "L'API doit renvoyer les informations relevées"
    for champ in donnees["informations"]:
        assert champ["explication"], f"Information sans explication : {champ['libelle']}"
        assert "Aucune explication rédigée" not in champ["explication"]

    assert donnees["risque"]["elements"], "L'API doit expliquer chaque signal du score"
    for element in donnees["risque"]["elements"]:
        assert element["explication"]
