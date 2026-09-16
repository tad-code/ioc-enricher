/*
 * Confirmation avant suppression d'une analyse de l'historique.
 *
 * Fichier séparé (et non un attribut « onsubmit » dans le HTML) pour pouvoir
 * appliquer une politique de sécurité stricte (CSP) sans autoriser le
 * JavaScript en ligne.
 */
document.addEventListener("submit", function (evenement) {
  var formulaire = evenement.target;
  if (formulaire && formulaire.matches("form[data-confirm]")) {
    if (!window.confirm(formulaire.dataset.confirm)) {
      evenement.preventDefault();
    }
  }
});
