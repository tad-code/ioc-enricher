"""
Génère les captures d'écran du README à partir de l'application déployée.

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


def capture(chemin):
    return os.path.join(DOSSIER, chemin)


with sync_playwright() as play:
    navigateur = play.chromium.launch(channel="chrome", headless=True)
    page = navigateur.new_page(viewport={"width": 1440, "height": 1000})

    # 1. Page d'accueil (formulaire + historique)
    page.goto(BASE, wait_until="networkidle")
    page.screenshot(path=capture("capture-accueil.png"), full_page=True)
    print("capture-accueil.png")

    # 2. Rapport d'analyse d'une adresse IP
    page.fill("input[name=ioc]", "185.220.101.1")
    page.click("button[type=submit]")
    page.wait_for_selector("text=Justification du score", timeout=90_000)
    page.screenshot(path=capture("capture-rapport.png"), full_page=True)
    print("capture-rapport.png")

    # 3. Réponse JSON brute de l'API (section dépliée)
    page.click("summary")
    page.wait_for_timeout(600)
    page.screenshot(path=capture("capture-json.png"), full_page=True)
    print("capture-json.png")

    # 4. Analyse d'un domaine
    page.fill("input[name=ioc]", "github.com")
    page.click("button[type=submit]")
    page.wait_for_selector("text=Justification du score", timeout=90_000)
    page.screenshot(path=capture("capture-domaine.png"), full_page=True)
    print("capture-domaine.png")

    navigateur.close()

print("Captures enregistrées dans", DOSSIER)
