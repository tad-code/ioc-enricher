"""
Tests unitaires du socle Python (aucun appel réseau, aucune base de données).

Lancement :
    python -m pytest -v
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ioc_parser import detect_type, parse_ioc, refang  # noqa: E402
import scoring  # noqa: E402


# ---------------------------------------------------------------------------
# Détection et validation du type d'IOC
# ---------------------------------------------------------------------------

def test_detecte_une_adresse_ip():
    assert detect_type("185.10.10.5") == "ip"
    assert detect_type("2001:4860:4860::8888") == "ip"


def test_detecte_un_domaine():
    assert detect_type("evil-corp.com") == "domain"
    assert detect_type("sous.domaine.exemple.org") == "domain"


def test_detecte_un_hash():
    assert detect_type("44d88612fea8a8f36de82e1278abb02f") == "hash"                      # MD5
    assert detect_type("a" * 40) == "hash"                                               # SHA1
    assert detect_type("b" * 64) == "hash"                                               # SHA256


def test_refang():
    assert refang("185[.]10[.]10[.]5") == "185.10.10.5"
    assert refang("hxxps://evil[.]com") == "https://evil.com"


def test_parse_ioc_normalise_le_domaine():
    resultat = parse_ioc("  Evil-Corp.COM  ")
    assert resultat["ok"] is True
    assert resultat["ioc"] == "evil-corp.com"
    assert resultat["type"] == "domain"


def test_parse_ioc_accepte_une_url_complete():
    resultat = parse_ioc("https://evil-corp.com/login?id=1")
    assert resultat["ok"] is True
    assert resultat["ioc"] == "evil-corp.com"


def test_parse_ioc_saisie_vide():
    resultat = parse_ioc("   ")
    assert resultat["ok"] is False
    assert "Aucune valeur" in resultat["error"]


def test_parse_ioc_saisie_invalide():
    resultat = parse_ioc("ceci n'est pas un ioc !")
    assert resultat["ok"] is False
    assert resultat["type"] is None


def test_parse_ioc_detecte_une_ip_privee():
    resultat = parse_ioc("192.168.1.10")
    assert resultat["ok"] is True
    assert "privée" in resultat["detail"].lower()


# ---------------------------------------------------------------------------
# Moteur de score
# ---------------------------------------------------------------------------

def test_niveau_par_fourchette():
    assert scoring.level_for(10) == "LOW"
    assert scoring.level_for(30) == "MEDIUM"
    assert scoring.level_for(60) == "HIGH"
    assert scoring.level_for(90) == "CRITICAL"


def test_reputation_associee_au_niveau():
    assert scoring.reputation_for("CRITICAL") == "MALVEILLANT"
    assert scoring.reputation_for("HIGH") == "SUSPECT"
    assert scoring.reputation_for("MEDIUM") == "DOUTEUX"
    assert scoring.reputation_for("LOW") == "SAIN"


def test_le_resultat_contient_la_reputation():
    resultat = scoring.compute_risk("ip", {"signals": [], "data": {}})
    assert resultat["reputation"] in ("MALVEILLANT", "SUSPECT", "DOUTEUX", "SAIN")


def test_score_augmente_avec_les_signaux():
    faible = scoring.compute_risk("ip", {"signals": [{"points": 5, "label": "test"}], "data": {}})
    fort = scoring.compute_risk("ip", {"signals": [{"points": 70, "label": "test"}], "data": {}})
    assert fort["score"] > faible["score"]
    assert fort["level"] in ("HIGH", "CRITICAL")


def test_score_borne_entre_0_et_100():
    resultat = scoring.compute_risk("ip", {"signals": [{"points": 500, "label": "abusif"}], "data": {}})
    assert resultat["score"] == 100


def test_tld_suspect_est_une_raison():
    resultat = scoring.compute_risk("domain", {"signals": [], "ioc": "promo-cadeau.xyz", "data": {}})
    assert any("xyz" in raison for raison in resultat["reasons"])


def test_un_domaine_ancien_reduit_le_score():
    resultat = scoring.compute_risk("domain", {"signals": [{"points": -10, "label": "ancien"}], "ioc": "gouv.ci", "data": {}})
    assert resultat["score"] < scoring.BASE_SCORE
