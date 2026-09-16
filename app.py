"""
IOC ENRICHER — enrichissement d'indicateurs de compromission.

Application web Flask qui permet à un analyste SOC de :
  1. saisir un indicateur de compromission (IP, domaine ou hash) ;
  2. faire identifier et valider automatiquement son type ;
  3. interroger une API externe d'enrichissement et récupérer du JSON ;
  4. obtenir un rapport structuré avec un niveau de risque justifié ;
  5. enregistrer l'analyse dans une base de données PostgreSQL (Supabase) ;
  6. consulter et supprimer l'historique des analyses.

Lancement en local :
    python app.py            ->  http://127.0.0.1:5000
"""

from __future__ import annotations

import logging
import os

from dotenv import load_dotenv
from flask import Flask, render_template, request

import db
import scoring
from enrichment import EnrichmentError, enrich
from ioc_parser import TYPES, parse_ioc

# Charge le fichier .env (identifiants de la base, clé API éventuelle).
# En production (Vercel), les variables viennent des Environment Variables.
load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("ioc-enricher")

app = Flask(__name__)

# Sécurité : on refuse les requêtes dont le corps dépasse 16 Ko. Un IOC tient en
# quelques dizaines de caractères ; au-delà, c'est une tentative d'abus.
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

# En-têtes de sécurité appliqués à toutes les réponses.
# Ils sont définis ici (et non dans vercel.json) car le déploiement utilise la
# section « routes », qui prend le pas sur la section « headers ».
ENTETES_SECURITE = {
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "script-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Robots-Tag": "noindex, nofollow",
}


@app.after_request
def ajouter_entetes_securite(reponse):
    """Ajoute les en-têtes de sécurité à chaque réponse HTTP."""
    for nom, valeur in ENTETES_SECURITE.items():
        reponse.headers.setdefault(nom, valeur)
    return reponse


# ---------------------------------------------------------------------------
# Fonctions utilitaires
# ---------------------------------------------------------------------------

def render_home(**contexte):
    """Affiche la page principale en y injectant l'historique des analyses.

    L'historique est rechargé à chaque affichage : si la base est injoignable,
    la page reste utilisable et un bandeau explique le problème.
    """
    historique, erreur_db = db.list_analyses(limit=25)
    contexte.setdefault("history", historique)
    contexte.setdefault("db_error", erreur_db)
    contexte.setdefault("total", len(historique))
    contexte["db_ready"] = db.is_configured()
    contexte.setdefault("result", None)
    contexte.setdefault("error", None)
    contexte.setdefault("notice", None)
    contexte.setdefault("form_value", "")
    contexte["types"] = TYPES
    return render_template("index.html", **contexte)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def home():
    """Page d'accueil : formulaire de saisie + historique des analyses."""
    return render_home()


@app.route("/analyze", methods=["POST"])
def analyze():
    """Cœur de l'application : analyse d'un IOC soumis par l'utilisateur."""
    valeur_saisie = request.form.get("ioc", "")

    # --- Étape 1 : validation de la saisie -------------------------------
    analyse = parse_ioc(valeur_saisie)
    if not analyse["ok"]:
        return render_home(error=analyse["error"], form_value=valeur_saisie), 400

    # --- Étape 2 : appel de l'API externe --------------------------------
    try:
        enrichissement = enrich(analyse["ioc"], analyse["type"])
    except EnrichmentError as exc:
        log.warning("Enrichissement impossible pour %s : %s", analyse["ioc"], exc)
        return render_home(
            error=f"Enrichissement impossible ({exc.kind}) : {exc}",
            form_value=valeur_saisie,
        ), 502

    # --- Étape 3 : calcul du niveau de risque ----------------------------
    risque = scoring.compute_risk(analyse["type"], enrichissement)

    resultat = {
        "ioc": analyse["ioc"],
        "ioc_type": analyse["type"],
        "ioc_type_label": TYPES.get(analyse["type"], analyse["type"]),
        "detail": analyse["detail"],
        "enrichissement": enrichissement,
        "risque": risque,
    }

    # --- Étape 4 : enregistrement en base de données ---------------------
    try:
        ligne = db.save_analysis(
            ioc=analyse["ioc"],
            ioc_type=analyse["type"],
            risk_level=risque["level"],
            risk_score=risque["score"],
            source_api=enrichissement["source"],
            summary={
                "reputation": risque["reputation"],
                "http_status": enrichissement["http_status"],
                "endpoint": enrichissement["endpoint"],
                "fields": enrichissement["fields"],
                "notes": enrichissement.get("notes", []),
            },
            reasons=risque["reasons"],
        )
        resultat["saved"] = bool(ligne)
        resultat["row_id"] = ligne.get("id")
        resultat["created_at"] = ligne.get("created_at")
        avis = None
    except db.DatabaseError as exc:
        # L'analyse reste affichée même si la sauvegarde échoue : on ne perd pas
        # le travail de l'analyste à cause d'un incident de base de données.
        log.warning("Sauvegarde impossible : %s", exc)
        resultat["saved"] = False
        avis = f"Analyse effectuée, mais NON enregistrée dans l'historique ({exc.kind}) : {exc}"

    return render_home(result=resultat, notice=avis, form_value="")


@app.route("/delete/<int:row_id>", methods=["POST"])
def delete(row_id: int):
    """Supprime une analyse de l'historique (bouton « Supprimer »)."""
    try:
        db.delete_analysis(row_id)
    except db.DatabaseError as exc:
        return render_home(error=f"Suppression impossible ({exc.kind}) : {exc}")
    return render_home(notice=f"Analyse n°{row_id} supprimée de l'historique.")


@app.route("/health")
def health():
    """Sonde de supervision volontairement minimale.

    Elle ne renvoie ni configuration, ni statistiques de base de données :
    ce genre d'information ne doit pas être exposé publiquement.
    """
    return {"status": "ok", "service": "ioc-enricher"}


# ---------------------------------------------------------------------------
# Gestion des erreurs
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def page_introuvable(_erreur):
    return render_home(error="Page introuvable. Revenez à l'accueil pour lancer une analyse."), 404


@app.errorhandler(405)
def methode_non_autorisee(_erreur):
    return render_home(error="Méthode HTTP non autorisée sur cette adresse."), 405


@app.errorhandler(413)
def requete_trop_volumineuse(_erreur):
    return render_home(error="Requête refusée : la saisie est trop volumineuse (16 Ko maximum)."), 413


@app.errorhandler(500)
def erreur_interne(_erreur):
    log.exception("Erreur interne non gérée")
    return render_home(error="Une erreur interne est survenue. L'incident a été journalisé."), 500


if __name__ == "__main__":
    # host=0.0.0.0 permet de tester depuis un autre appareil du réseau local.
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)
