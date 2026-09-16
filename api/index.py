"""
Point d'entrée pour le déploiement serverless sur Vercel.

Vercel exécute le fichier api/index.py comme une fonction Python. On y importe
simplement l'application Flask définie à la racine du projet, après avoir
ajouté la racine au chemin de recherche des modules Python.
"""

import os
import sys

RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if RACINE not in sys.path:
    sys.path.insert(0, RACINE)

from app import app  # noqa: E402  (import après ajustement du sys.path)

# Vercel cherche un objet WSGI nommé "app" : c'est notre application Flask.
__all__ = ["app"]
