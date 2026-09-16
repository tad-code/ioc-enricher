"""
IOC ENRICHER — enrichissement d'indicateurs de compromission.

Application web Flask qui permet à un analyste SOC de :
  1. saisir un indicateur de compromission (IP, domaine ou hash) — ou
     plusieurs d'un coup en mode « analyse par lots » ;
  2. faire identifier et valider automatiquement son type ;
  3. interroger des API externes d'enrichissement et récupérer du JSON ;
  4. obtenir un rapport structuré : réputation, niveau de risque justifié
     et action recommandée ;
  5. repérer les indicateurs déjà analysés (mode « déjà vu ») ;
  6. enregistrer l'analyse dans une base de données PostgreSQL (Supabase) ;
  7. consulter, exporter (CSV) et supprimer l'historique ;
  8. exposer le moteur en JSON via /api/analyze et /api/history.

Lancement en local :
    python app.py            ->  http://127.0.0.1:5000
"""

from __future__ import annotations

import csv
import io
import logging
import os
import time

from dotenv import load_dotenv
from flask import Flask, Response, jsonify, render_template, request

import db
import scoring
from enrichment import EnrichmentError, enrich
from ioc_parser import TYPES, parse_ioc, parse_many

# Charge le fichier .env (identifiants de la base, clé API éventuelle).
# En production (Vercel), les variables viennent des Environment Variables.
load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("ioc-enricher")

app = Flask(__name__)

# Sécurité : on refuse les requêtes dont le corps dépasse 16 Ko. Un IOC tient en
# quelques dizaines de caractères ; au-delà, c'est une tentative d'abus.
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

# Mode « analyse par lots » : au-delà de 5 indicateurs, la fonction serverless
# dépasserait son temps d'exécution maximum (30 s sur Vercel). On borne donc le
# travail et on prévient l'utilisateur (voir analyser_lot).
MAX_LOT = 5
BUDGET_LOT_SECONDES = 20

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
# Moteur d'analyse
# ---------------------------------------------------------------------------

def analyser_ioc(ioc: str, ioc_type: str, *, sauvegarder: bool = True):
    """Enrichit un IOC, calcule son risque et l'enregistre.

    Retourne (resultat, avis) :
      * resultat : dictionnaire complet pour l'affichage ;
      * avis     : message d'avertissement à afficher (ou None).

    Lève EnrichmentError si l'API externe ne répond pas.
    """
    enrichissement = enrich(ioc, ioc_type)
    risque = scoring.compute_risk(ioc_type, enrichissement)

    resultat = {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "ioc_type_label": TYPES.get(ioc_type, ioc_type),
        "enrichissement": enrichissement,
        "risque": risque,
        "saved": False,
    }

    if not sauvegarder:
        return resultat, None

    try:
        ligne = db.save_analysis(
            ioc=ioc,
            ioc_type=ioc_type,
            risk_level=risque["level"],
            risk_score=risque["score"],
            source_api=enrichissement["source"],
            summary={
                "reputation": risque["reputation"],
                "action": risque["action"],
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
        return resultat, None
    except db.DatabaseError as exc:
        # L'analyse reste affichée même si la sauvegarde échoue : on ne perd pas
        # le travail de l'analyste à cause d'un incident de base de données.
        log.warning("Sauvegarde impossible : %s", exc)
        return resultat, (
            f"Analyse effectuée, mais NON enregistrée dans l'historique ({exc.kind}) : {exc}"
        )


def analyser_lot(analyses: list) -> list:
    """Analyse plusieurs IOC à la suite, dans un budget de temps donné.

    Le temps est surveillé à chaque tour de boucle : on préfère rendre un
    résultat partiel propre plutôt que de laisser mourir la fonction serverless
    en plein traitement.
    """
    debut = time.monotonic()
    resultats = []

    for analyse in analyses:
        ioc = analyse["ioc"]

        if time.monotonic() - debut > BUDGET_LOT_SECONDES:
            resultats.append({
                "ioc": ioc,
                "statut": "ignoré",
                "message": "limite de temps atteinte : relancez-le seul",
                "level": None, "reputation": None, "score": None, "source": None,
                "ioc_type_label": TYPES.get(analyse["type"], analyse["type"]),
            })
            continue

        try:
            resultat, avis = analyser_ioc(ioc, analyse["type"])
        except EnrichmentError as exc:
            resultats.append({
                "ioc": ioc,
                "statut": "erreur API",
                "message": str(exc),
                "level": None, "reputation": None, "score": None, "source": None,
                "ioc_type_label": TYPES.get(analyse["type"], analyse["type"]),
            })
            continue

        resultats.append({
            "ioc": ioc,
            "ioc_type_label": TYPES.get(analyse["type"], analyse["type"]),
            "statut": "enregistré" if resultat["saved"] else "analyse seule",
            "message": avis or resultat["enrichissement"]["source"],
            "level": resultat["risque"]["level"],
            "reputation": resultat["risque"]["reputation"],
            "action": resultat["risque"]["action"],
            "score": resultat["risque"]["score"],
            "source": resultat["enrichissement"]["source"],
            "row_id": resultat.get("row_id"),
        })

    return resultats


def statistiques(historique: list) -> dict:
    """Calcule les statistiques du tableau de bord.

    Tout est fait en Python avec des dictionnaires et des boucles — c'est le
    genre de traitement qui justifie une base de données : agréger un historique
    plutôt que le relire ligne par ligne.
    """
    par_risque = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    par_type = {"ip": 0, "domain": 0, "hash": 0}
    par_source = {}
    scores = []

    for ligne in historique:
        niveau = ligne.get("risk_level")
        if niveau in par_risque:
            par_risque[niveau] += 1

        type_ioc = ligne.get("ioc_type")
        if type_ioc in par_type:
            par_type[type_ioc] += 1

        source = ligne.get("source_api") or "inconnue"
        par_source[source] = par_source.get(source, 0) + 1

        try:
            scores.append(int(ligne.get("risk_score") or 0))
        except (TypeError, ValueError):
            pass

    total = len(historique)
    plus_utilisees = sorted(par_source.items(), key=lambda couple: (-couple[1], couple[0]))[:4]

    return {
        "total": total,
        "par_risque": par_risque,
        "par_type": par_type,
        "sources": plus_utilisees,
        "score_moyen": round(sum(scores) / len(scores)) if scores else 0,
        "premiere": historique[-1]["created_at"] if historique else None,
        "derniere": historique[0]["created_at"] if historique else None,
        "sources_distinctes": len(par_source),
    }


# ---------------------------------------------------------------------------
# Rendu de la page
# ---------------------------------------------------------------------------

def render_home(**contexte):
    """Affiche la page principale en y injectant l'historique et les statistiques.

    L'historique est rechargé à chaque affichage : si la base est injoignable,
    la page reste utilisable et un bandeau explique le problème.
    """
    historique, erreur_db = db.list_analyses(limit=25)
    etendue, _ = db.list_analyses_large(limit=500)

    contexte.setdefault("history", historique)
    contexte.setdefault("db_error", erreur_db)
    contexte.setdefault("total", len(historique))
    contexte["stats"] = statistiques(etendue)
    contexte["db_ready"] = db.is_configured()
    contexte.setdefault("result", None)
    contexte.setdefault("lot", None)
    contexte.setdefault("lot_erreurs", None)
    contexte.setdefault("ignorees", 0)
    contexte.setdefault("error", None)
    contexte.setdefault("notice", None)
    contexte.setdefault("form_value", "")
    contexte["types"] = TYPES
    contexte["max_lot"] = MAX_LOT
    return render_template("index.html", **contexte)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def home():
    """Page d'accueil : formulaire, tableau de bord, historique."""
    return render_home()


@app.route("/analyze", methods=["POST"])
def analyze():
    """Cœur de l'application : analyse d'un ou plusieurs IOC."""
    valeur_saisie = request.form.get("ioc", "")

    # --- Mode lot : plusieurs indicateurs collés d'un coup ----------------
    lot = parse_many(valeur_saisie, maximum=MAX_LOT)
    if lot["total"] > 1:
        if not lot["analyses"]:
            return render_home(
                error="Aucun des indicateurs fournis n'est valide.",
                lot_erreurs=lot["erreurs"],
                form_value=valeur_saisie,
            ), 400
        resultats = analyser_lot(lot["analyses"])
        return render_home(
            lot=resultats,
            lot_erreurs=lot["erreurs"],
            ignorees=lot["ignorees"],
            form_value="",
        )

    # --- Mode simple : un seul indicateur ---------------------------------
    analyse = parse_ioc(valeur_saisie)
    if not analyse["ok"]:
        return render_home(error=analyse["error"], form_value=valeur_saisie), 400

    # L'IOC a-t-il déjà été analysé ? (avant l'enregistrement, évidemment)
    precedente = db.find_last_analysis(analyse["ioc"])

    try:
        resultat, avis = analyser_ioc(analyse["ioc"], analyse["type"])
    except EnrichmentError as exc:
        log.warning("Enrichissement impossible pour %s : %s", analyse["ioc"], exc)
        return render_home(
            error=f"Enrichissement impossible ({exc.kind}) : {exc}",
            form_value=valeur_saisie,
        ), 502

    resultat["detail"] = analyse["detail"]
    resultat["precedente"] = precedente
    if precedente:
        try:
            resultat["evolution"] = resultat["risque"]["score"] - int(precedente.get("risk_score") or 0)
        except (TypeError, ValueError):
            resultat["evolution"] = None

    return render_home(result=resultat, notice=avis, form_value="")


@app.route("/delete/<int:row_id>", methods=["POST"])
def delete(row_id: int):
    """Supprime une analyse de l'historique (bouton « Supprimer »)."""
    try:
        db.delete_analysis(row_id)
    except db.DatabaseError as exc:
        return render_home(error=f"Suppression impossible ({exc.kind}) : {exc}")
    return render_home(notice=f"Analyse n°{row_id} supprimée de l'historique.")


@app.route("/export.csv")
def export_csv():
    """Exporte tout l'historique en CSV (ouvrable dans Excel / LibreOffice)."""
    lignes, erreur = db.list_analyses_large(limit=500)
    if erreur:
        return render_home(error=f"Export impossible : {erreur}"), 502

    tampon = io.StringIO()
    # Point-virgule comme séparateur : c'est ce qu'attend Excel en français.
    ecrivain = csv.writer(tampon, delimiter=";")
    ecrivain.writerow(["id", "ioc", "type", "reputation", "risque", "score",
                       "source_api", "date", "raisons"])
    for ligne in lignes:
        resume = ligne.get("summary") or {}
        ecrivain.writerow([
            ligne.get("id"),
            ligne.get("ioc"),
            ligne.get("ioc_type"),
            resume.get("reputation", ""),
            ligne.get("risk_level"),
            ligne.get("risk_score"),
            ligne.get("source_api"),
            ligne.get("created_at"),
            " | ".join(ligne.get("reasons") or []),
        ])

    # utf-8-sig ajoute le BOM : sans lui, Excel affiche mal les accents.
    contenu = tampon.getvalue().encode("utf-8-sig")
    return Response(
        contenu,
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=historique-ioc.csv",
            "Cache-Control": "no-store",
        },
    )


@app.route("/api/analyze")
def api_analyze():
    """API JSON : /api/analyze?ioc=185.220.101.1&save=0

    Permet à un autre outil (script, tableur, futur SOAR) d'utiliser le moteur
    d'enrichissement sans passer par l'interface web.
    """
    valeur = request.args.get("ioc", "")
    sauvegarder = request.args.get("save", "1").lower() not in ("0", "false", "non")

    analyse = parse_ioc(valeur)
    if not analyse["ok"]:
        return jsonify({"ok": False, "erreur": analyse["error"]}), 400

    try:
        resultat, avis = analyser_ioc(analyse["ioc"], analyse["type"], sauvegarder=sauvegarder)
    except EnrichmentError as exc:
        return jsonify({"ok": False, "erreur": str(exc), "type_erreur": exc.kind}), 502

    enrichissement = resultat["enrichissement"]
    risque = resultat["risque"]
    return jsonify({
        "ok": True,
        "ioc": resultat["ioc"],
        "type": analyse["type"],
        "reputation": risque["reputation"],
        "action": risque["action"],
        "risque": {
            "niveau": risque["level"],
            "score": risque["score"],
            "raisons": risque["reasons"],
        },
        "source": enrichissement["source"],
        "http_status": enrichissement["http_status"],
        "endpoint": enrichissement["endpoint"],
        "informations": enrichissement["fields"],
        "enregistre": resultat["saved"],
        "avertissement": avis,
    })


@app.route("/api/history")
def api_history():
    """API JSON : /api/history?limit=25 — historique des analyses."""
    try:
        limite = min(max(int(request.args.get("limit", 25)), 1), 100)
    except ValueError:
        return jsonify({"ok": False, "erreur": "Le paramètre limit doit être un nombre."}), 400

    lignes, erreur = db.list_analyses(limit=limite)
    if erreur:
        return jsonify({"ok": False, "erreur": erreur}), 502
    return jsonify({"ok": True, "nombre": len(lignes), "analyses": lignes})


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
