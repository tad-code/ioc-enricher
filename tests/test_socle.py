"""
Tests unitaires du socle Python (aucun appel réseau, aucune base de données).

Lancement :
    python -m pytest -v
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ioc_parser import detect_type, decoupe_iocs, parse_ioc, parse_many, portee_ip, refang  # noqa: E402
import enrichment  # noqa: E402
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
# Adresses IP impossibles : refusées avant la détection de type
# ---------------------------------------------------------------------------

def test_parse_ioc_refuse_une_adresse_ip_impossible():
    """« 300.300.300.300 » a la forme d'une IP mais n'en est pas une.

    Un nom de domaine peut contenir des labels numériques : sans contrôle
    dédié, cette saisie satisfaisait l'expression régulière des domaines et
    était donc analysée comme un domaine suspect, à 55/100.
    """
    for saisie in ("300.300.300.300", "999.1.1.1", "1.2.3.999", "256.0.0.1"):
        resultat = parse_ioc(saisie)
        assert resultat["ok"] is False, saisie
        assert resultat["type"] is None, saisie
        assert "entre 0 et 255" in resultat["error"], saisie


def test_une_adresse_ip_impossible_n_est_pas_prise_pour_un_domaine():
    """Le message d'erreur doit parler d'adresse, pas de domaine."""
    resultat = parse_ioc("300.300.300.300")
    assert "domaine" not in resultat["error"].lower()


def test_les_adresses_ip_valides_restent_acceptees():
    """Garde-fou : le contrôle ajouté ne doit rejeter aucune adresse légitime."""
    for saisie in ("0.0.0.0", "255.255.255.255", "8.8.8.8", "1.1.1.1", "192.168.1.1"):
        resultat = parse_ioc(saisie)
        assert resultat["ok"] is True, saisie
        assert resultat["type"] == "ip", saisie


# ---------------------------------------------------------------------------
# Normalisation des saisies copiées d'un journal ou d'un rapport
# ---------------------------------------------------------------------------

def test_port_retire_de_l_adresse_ip():
    """« 8.8.8.8:8080 » doit être reconnu comme une adresse, pas comme un domaine.

    Un analyste copie très souvent « adresse:port » depuis un journal de
    connexion. Sans nettoyage, la chaîne retombait dans la détection de domaine
    et recevait 40/100.
    """
    resultat = parse_ioc("8.8.8.8:8080")
    assert resultat["ok"] is True
    assert resultat["type"] == "ip"
    assert resultat["ioc"] == "8.8.8.8"


def test_port_retire_du_domaine():
    resultat = parse_ioc("exemple.com:443")
    assert resultat["ok"] is True
    assert resultat["type"] == "domain"
    assert resultat["ioc"] == "exemple.com"


def test_une_ipv6_n_est_pas_alteree_par_le_retrait_de_port():
    """Les deux-points d'une IPv6 font partie de l'adresse, pas d'un port."""
    for saisie in ("2001:4860:4860::8888", "fe80::1", "::1"):
        resultat = parse_ioc(saisie)
        assert resultat["ok"] is True, saisie
        assert resultat["type"] == "ip", saisie


def test_le_prefixe_www_est_retire():
    """www.github.com et github.com désignent le même domaine analysé."""
    avec = parse_ioc("www.github.com")
    sans = parse_ioc("github.com")
    assert avec["ok"] is True and sans["ok"] is True
    assert avec["ioc"] == sans["ioc"] == "github.com"
    assert avec["type"] == "domain"


def test_un_domaine_en_www_a_trois_niveaux_reste_intact():
    """Le nettoyage ne doit pas abîmer un sous-domaine réellement distinct."""
    resultat = parse_ioc("www.monentreprise.example.com")
    assert resultat["ok"] is True
    assert resultat["ioc"] == "monentreprise.example.com"


# ---------------------------------------------------------------------------
# Mode « analyse par lots »
# ---------------------------------------------------------------------------

def test_decoupe_iocs_separe_lignes_et_virgules():
    valeurs = decoupe_iocs("8.8.8.8\ngithub.com, 44d88612fea8a8f36de82e1278abb02f")
    assert valeurs == ["8.8.8.8", "github.com", "44d88612fea8a8f36de82e1278abb02f"]


def test_decoupe_iocs_supprime_les_doublons():
    assert decoupe_iocs("8.8.8.8,8.8.8.8;8.8.8.8") == ["8.8.8.8"]


def test_decoupe_iocs_borne_la_liste():
    texte = "\n".join(f"10.0.0.{i}" for i in range(1, 20))
    assert len(decoupe_iocs(texte, maximum=5)) == 5


def test_parse_many_separe_valides_et_erreurs():
    resultat = parse_many("8.8.8.8\nceci n'est pas un ioc\ngithub.com")
    assert len(resultat["analyses"]) == 2
    assert len(resultat["erreurs"]) == 1
    assert resultat["ignorees"] == 0


def test_parse_many_signale_le_surplus():
    resultat = parse_many("\n".join(f"10.0.0.{i}" for i in range(1, 9)), maximum=5)
    assert len(resultat["analyses"]) == 5
    assert resultat["ignorees"] == 3


# ---------------------------------------------------------------------------
# Action recommandée
# ---------------------------------------------------------------------------

def test_action_pour_chaque_niveau():
    assert scoring.action_for("CRITICAL") == "BLOQUER IMMÉDIATEMENT"
    assert scoring.action_for("HIGH") == "BLOQUER ET INVESTIGUER"
    assert scoring.action_for("MEDIUM") == "SURVEILLER"
    assert scoring.action_for("LOW") == "AUCUNE ACTION"


def test_le_resultat_contient_l_action():
    resultat = scoring.compute_risk("ip", {"signals": [], "data": {}})
    assert resultat["action"] in scoring.ACTIONS.values()


# ---------------------------------------------------------------------------
# Statistiques du tableau de bord
# ---------------------------------------------------------------------------

def test_statistiques_calculent_la_repartition():
    from app import statistiques

    historique = [
        {"risk_level": "HIGH", "ioc_type": "ip", "risk_score": "70",
         "source_api": "ip-api.com", "created_at": "2026-09-16T10:00:00"},
        {"risk_level": "LOW", "ioc_type": "domain", "risk_score": 0,
         "source_api": "RDAP", "created_at": "2026-09-16T09:00:00"},
    ]
    stats = statistiques(historique)

    assert stats["total"] == 2
    assert stats["par_risque"]["HIGH"] == 1
    assert stats["par_risque"]["CRITICAL"] == 0
    assert stats["par_type"]["domain"] == 1
    assert stats["score_moyen"] == 35
    assert stats["sources_distinctes"] == 2
    assert stats["derniere"].startswith("2026-09-16T10")
    assert stats["premiere"].startswith("2026-09-16T09")


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


def test_le_datacenter_seul_ne_rend_pas_une_adresse_douteuse():
    """Un hébergement en datacenter ne suffit pas à qualifier une adresse.

    Tout serveur DNS public, tout CDN et tout service en nuage sont hébergés en
    datacenter. Si ce signal seul faisait franchir le seuil du niveau
    intermédiaire, 8.8.8.8 (Google DNS) et 1.1.1.1 (Cloudflare) seraient
    affichés « DOUTEUX » — un faux positif que le premier visiteur venu
    relèverait, et qui décrédibilise tout le score.
    """
    resultat = scoring.compute_risk(
        "ip", {"signals": [{"points": 10, "label": "hébergé dans un datacenter"}], "data": {}}
    )
    assert resultat["level"] == "LOW", resultat
    assert resultat["reputation"] == "SAIN"


def test_le_datacenter_compte_toujours_en_combinaison():
    """Le signal reste utile : associé à un proxy, il fait monter le niveau."""
    resultat = scoring.compute_risk(
        "ip",
        {
            "signals": [
                {"points": 10, "label": "hébergé dans un datacenter"},
                {"points": 35, "label": "proxy / VPN / Tor"},
            ],
            "data": {},
        },
    )
    assert resultat["score"] >= 50, resultat
    assert resultat["level"] in ("HIGH", "CRITICAL")


def test_un_signal_moyen_isole_plafonne_au_niveau_intermediaire():
    """Un proxy ou un VPN n'est pas en soi une preuve de malveillance."""
    resultat = scoring.compute_risk(
        "ip", {"signals": [{"points": 35, "label": "proxy / VPN / Tor"}], "data": {}}
    )
    assert resultat["level"] == "MEDIUM", resultat


def test_tld_suspect_est_une_raison():
    resultat = scoring.compute_risk("domain", {"signals": [], "ioc": "promo-cadeau.xyz", "data": {}})
    assert any("xyz" in raison for raison in resultat["reasons"])


def test_un_domaine_ancien_reduit_le_score():
    resultat = scoring.compute_risk("domain", {"signals": [{"points": -10, "label": "ancien"}], "ioc": "gouv.ci", "data": {}})
    assert resultat["score"] < scoring.BASE_SCORE


# ---------------------------------------------------------------------------
# Portée des adresses IP : privées, locales, réservées (aucun appel réseau)
# ---------------------------------------------------------------------------

def test_adresse_publique_n_a_pas_de_portee_particuliere():
    """Une adresse routable part vers l'API : portee_ip retourne None."""
    assert portee_ip("8.8.8.8") is None
    assert portee_ip("185.220.101.1") is None
    assert portee_ip("2001:4860:4860::8888") is None


def test_adresses_privees_reconnues():
    assert portee_ip("192.168.1.1")["portee"] == "privée"
    assert portee_ip("10.0.0.1")["portee"] == "privée"
    assert portee_ip("172.16.5.4")["portee"] == "privée"


def test_adresses_locales_et_lien_local():
    assert portee_ip("127.0.0.1")["portee"] == "locale"
    assert portee_ip("::1")["portee"] == "locale"
    assert portee_ip("169.254.1.1")["portee"] == "lien-local"
    assert portee_ip("fe80::1")["portee"] == "lien-local"


def test_adresses_non_routables_diverses():
    assert portee_ip("0.0.0.0")["portee"] == "non spécifiée"
    assert portee_ip("224.0.0.1")["portee"] == "multicast"
    assert portee_ip("pas-une-ip") is None


def test_adresse_privee_est_analysee_sans_appel_reseau():
    """Le cas qui échouait : 192.168.1.1 doit rendre un VERDICT, pas une erreur."""
    enrichissement = enrichment.enrich("192.168.1.1", "ip")

    assert enrichissement["non_routable"] is True
    assert enrichissement["http_status"] is None      # aucun appel HTTP effectué
    assert "ip-api" not in enrichissement["source"]

    risque = scoring.compute_risk("ip", enrichissement)
    assert risque["score"] == 0
    assert risque["reputation"] == "HORS PÉRIMÈTRE"
    assert "INTERNE" in risque["action"]
    assert len(risque["reasons"]) == 3


def test_adresse_privee_expliquee_dans_les_champs():
    enrichissement = enrichment.enrich("192.168.1.1", "ip")
    champs = dict(enrichissement["fields"])

    assert champs["Routable sur Internet"] == "non"
    assert champs["Portée"] == "privée"
    assert "192.168.0.0/16" in champs["Plage d'appartenance"]
    assert "RFC 1918" in champs["Explication"]


# ---------------------------------------------------------------------------
# Pages web : jamais d'erreur brute pour un simple visiteur
# ---------------------------------------------------------------------------

def test_soumission_vide_invite_au_lieu_d_une_erreur():
    from app import app

    reponse = app.test_client().post("/analyze", data={"ioc": "   "})

    assert reponse.status_code == 200
    assert "Aucun indicateur saisi" in reponse.get_data(as_text=True)


def test_la_page_d_accueil_presente_l_outil():
    """Un visiteur qui n'ouvre qu'une page doit comprendre l'outil."""
    from app import app

    contenu = app.test_client().get("/").get_data(as_text=True)

    assert "Que fait cet outil" in contenu
    assert "indicateur de compromission" in contenu
    assert "Adresse IP suspecte" in contenu        # exemple lançable en un clic
    assert "Comment ça marche" in contenu
    assert "185.220.101.1" in contenu              # rapport d'exemple visible d'emblée
