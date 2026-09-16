"""
Génère les captures d'écran du README à partir de l'application déployée.

L'application est maintenant découpée en plusieurs pages : ce script capture
chaque page séparément, plus les écrans d'analyse.

Outil de documentation (optionnel) — nécessite Playwright, qui pilote ici le
Google Chrome déjà installé sur la machine :

    pip install playwright
    python tools/capture_screenshots.py https://ioc-enricher-delta.vercel.app
"""

import os
import sys

from playwright.sync_api import sync_playwright

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "https://ioc-enricher-delta.vercel.app"
DOSSIER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs")
os.makedirs(DOSSIER, exist_ok=True)


def capture(nom):
    return os.path.join(DOSSIER, nom)


def attendre_rapport(page):
    page.wait_for_selector("text=Justification du score", timeout=120_000)


with sync_playwright() as play:
    navigateur = play.chromium.launch(channel="chrome", headless=True)
    page = navigateur.new_page(viewport={"width": 1440, "height": 1000})

    # --- 1. Page d'analyse -------------------------------------------------
    page.goto(BASE, wait_until="networkidle")
    page.screenshot(path=capture("capture-analyse.png"), full_page=True)
    print("capture-analyse.png")

    # --- 2. Rapport d'une adresse IP --------------------------------------
    page.fill("textarea[name=ioc]", "185.220.101.1")
    page.click("button[type=submit]")
    attendre_rapport(page)
    page.screenshot(path=capture("capture-rapport.png"), full_page=True)
    print("capture-rapport.png")

    # --- 3. Réponse JSON brute (section dépliée) --------------------------
    page.click("summary")
    page.wait_for_timeout(600)
    page.screenshot(path=capture("capture-json.png"), full_page=True)
    print("capture-json.png")

    # --- 4. Analyse d'un domaine : SPF / DMARC ----------------------------
    page.goto(BASE, wait_until="networkidle")
    page.fill("textarea[name=ioc]", "github.com")
    page.click("button[type=submit]")
    attendre_rapport(page)
    page.screenshot(path=capture("capture-domaine.png"), full_page=True)
    print("capture-domaine.png")

    # --- 5. Mode « analyse par lots » -------------------------------------
    page.goto(BASE, wait_until="networkidle")
    page.fill("textarea[name=ioc]",
              "185.220.101.1\ngithub.com\npromo-cadeau-gratuit.xyz\n44d88612fea8a8f36de82e1278abb02f")
    page.click("button[type=submit]")
    page.wait_for_selector("text=Résultats du lot", timeout=180_000)
    page.screenshot(path=capture("capture-lot.png"), full_page=True)
    print("capture-lot.png")

    # --- 6. Tableau de bord -----------------------------------------------
    page.goto(BASE + "/tableau-de-bord", wait_until="networkidle")
    page.screenshot(path=capture("capture-tableau-de-bord.png"), full_page=True)
    print("capture-tableau-de-bord.png")

    # --- 7. Historique ----------------------------------------------------
    page.goto(BASE + "/historique", wait_until="networkidle")
    page.screenshot(path=capture("capture-historique.png"), full_page=True)
    print("capture-historique.png")

    # --- 8. Documentation de l'API ----------------------------------------
    page.goto(BASE + "/api", wait_until="networkidle")
    page.screenshot(path=capture("capture-api.png"), full_page=True)
    print("capture-api.png")

    navigateur.close()

print("Captures enregistrées dans", DOSSIER)
