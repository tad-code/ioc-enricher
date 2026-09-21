"""
Explications de chaque élément affiché par l'outil.

Principe directeur : **rien ne doit apparaître à l'écran sans être expliqué.**
Un rapport de renseignement qui affiche « AS13335 » ou « p=reject » sans dire ce
que c'est oblige le lecteur à faire confiance. L'outil doit au contraire être
capable de justifier chacun de ses éléments — c'est la différence entre un
tableau de bord et un outil d'analyse.

Ce module est la source unique de ces explications :

  * `CHAMPS`   : chaque information brute remontée par une source ;
  * `SIGNAUX`  : chaque raison qui pèse dans le score de risque ;
  * `CONCEPTS` : le vocabulaire employé, regroupé pour le glossaire.

Il est consommé à trois endroits, qui ne peuvent donc pas diverger : la page
d'analyse, l'API JSON, et la page de glossaire.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# 1) LES INFORMATIONS BRUTES
#
# Chaque entrée répond à deux questions :
#   - « explication » : qu'est-ce que c'est ?
#   - « pourquoi »    : qu'est-ce que ça change pour l'analyse ?
# ---------------------------------------------------------------------------

CHAMPS = {
    # --- Géolocalisation et réseau (ip-api.com) ---
    "Pays": {
        "explication": "Pays où le registre régional situe le bloc d'adresses auquel appartient cet indicateur.",
        "pourquoi": "Sert à situer l'infrastructure, jamais à conclure : un attaquant loue ses serveurs où bon lui semble, y compris dans des pays très surveillés ou très sûrs.",
    },
    "Pays (code)": {
        "explication": "Code pays sur deux lettres, tel que le déclare la source de réputation.",
        "pourquoi": "Permet de comparer cet indicateur à la zone géographique attendue par votre organisation.",
    },
    "Région": {
        "explication": "Découpage administratif à l'intérieur du pays (Land, État, province).",
        "pourquoi": "Précise la localisation quand un même opérateur possède plusieurs centres de données.",
    },
    "Ville": {
        "explication": "Commune associée au bloc d'adresses par le registre.",
        "pourquoi": "Utile pour corréler avec d'autres journaux : une connexion attribuée à une ville inattendue mérite un regard.",
    },
    "Coordonnées": {
        "explication": "Latitude et longitude estimées, au niveau du bloc d'adresses.",
        "pourquoi": "Indication approximative : elle désigne le centre de données ou le siège de l'opérateur, jamais la position d'une personne.",
    },
    "Fournisseur": {
        "explication": "Opérateur qui annonce ce bloc d'adresses sur Internet.",
        "pourquoi": "Un hébergeur professionnel et un fournisseur d'accès grand public n'ont pas le même profil de risque.",
    },
    "Fournisseur (ISP)": {
        "explication": "Opérateur (fournisseur d'accès ou hébergeur) à qui ce bloc a été attribué.",
        "pourquoi": "Un hébergeur professionnel et un fournisseur d'accès grand public n'ont pas le même profil de risque.",
    },
    "Organisation": {
        "explication": "Entité qui utilise concrètement l'adresse, différente de l'opérateur qui la transporte.",
        "pourquoi": "C'est souvent l'indice le plus parlant : une organisation inconnue derrière un grand opérateur signale une infrastructure de location.",
    },
    "ASN / Réseau": {
        "explication": "Numéro de système autonome : le numéro qui identifie, sur Internet, l'opérateur chargé d'annoncer ce bloc d'adresses auprès des autres réseaux.",
        "pourquoi": "Deux adresses appartenant au même numéro d'opérateur sont souvent exploitées par le même groupe. C'est un moyen direct de repérer une campagne menée depuis un hébergeur précis.",
    },
    "DNS inverse": {
        "explication": "Nom de domaine associé à l'adresse, obtenu en remontant du numéro vers le nom — l'inverse d'une résolution classique.",
        "pourquoi": "Révèle souvent l'usage réel d'une adresse. C'est ainsi qu'une adresse hébergée chez Cloudflare trahit, par son nom, le service qu'elle sert en réalité.",
    },
    "Datacenter": {
        "explication": "Indique si l'adresse appartient à un centre de données ou à un hébergeur professionnel, plutôt qu'à un abonnement grand public.",
        "pourquoi": "La plupart des serveurs malveillants sont loués à l'heure dans un centre de données, mais l'inverse n'est pas vrai : les serveurs de noms publics, les CDN et tous les services en nuage y sont aussi. Ce signal seul ne prouve rien.",
    },
    "Proxy / VPN": {
        "explication": "Indique si l'adresse est utilisée par un service qui masque l'origine réelle du trafic : réseau privé virtuel, proxy commercial ou nœud de sortie Tor.",
        "pourquoi": "Signale une volonté de dissimuler son origine. Ce n'est pas illégal en soi — beaucoup d'utilisateurs légitimes s'en servent — mais c'est un signal d'intérêt réel en analyse.",
    },
    "Type d'usage": {
        "explication": "Catégorie d'utilisation déclarée de l'adresse : accès résidentiel, hébergement, université, administration…",
        "pourquoi": "Permet de savoir si l'on a affaire à un particulier ou à une infrastructure professionnelle.",
    },
    "Score d'abus": {
        "explication": "Note de 0 à 100 attribuée par les signalements de la communauté des administrateurs systèmes. Plus elle est haute, plus l'adresse a été rapportée comme source d'attaques.",
        "pourquoi": "C'est un jugement humain agrégé, donc utile mais faillible : une adresse peu utilisée peut rester notée basse malgré une activité malveillante récente.",
    },
    "Signalements": {
        "explication": "Nombre de fois où cette adresse a été rapportée comme source d'abus par des administrateurs.",
        "pourquoi": "Un nombre élevé traduit une activité hostile observée et confirmée par plusieurs sources indépendantes.",
    },
    "Nœud de sortie Tor": {
        "explication": "Point de sortie du réseau d'anonymisation Tor : c'est par là que le trafic des utilisateurs de Tor arrive sur Internet.",
        "pourquoi": "Si une adresse est un nœud de sortie, les attaques attribuées à cette adresse peuvent venir de n'importe quel utilisateur de Tor. La conclusion « cette machine est malveillante » est alors à écarter.",
    },

    # --- Adresses non routables ---
    "Adresse analysée": {
        "explication": "Adresse telle qu'elle a été saisie, une fois remise en forme.",
        "pourquoi": "Permet de vérifier que l'outil a bien compris la saisie, en particulier après nettoyage d'une forme désamorcée.",
    },
    "Portée": {
        "explication": "Nature de l'adresse : publique, privée, locale, lien-local, multicast ou réservée.",
        "pourquoi": "Détermine si l'adresse existe réellement sur Internet. Une adresse privée ne peut être vue par aucune base publique.",
    },
    "Plage d'appartenance": {
        "explication": "Bloc d'adressage normalisé auquel appartient cette adresse, défini par les documents RFC.",
        "pourquoi": "Une plage privée identifie un réseau interne. L'outil peut donc nommer précisément pourquoi l'adresse est hors périmètre.",
    },
    "Explication": {
        "explication": "Raison pour laquelle cette adresse n'est pas analysable sur Internet.",
        "pourquoi": "Évite l'erreur classique consistant à chercher dans une base publique une adresse qui n'y figurera jamais.",
    },
    "Routable sur Internet": {
        "explication": "Indique si l'adresse peut circuler sur Internet public.",
        "pourquoi": "Quand la réponse est non, l'analyse doit se poursuivre dans les journaux internes, pas dans une API publique.",
    },
    "Sources publiques interrogeables": {
        "explication": "Indique si des bases publiques de renseignement peuvent répondre.",
        "pourquoi": "Quand aucune ne le peut, l'outil s'abstient d'appeler le réseau : il n'invente pas un score à partir de rien.",
    },

    # --- Domaine ---
    "Domaine": {
        "explication": "Nom de domaine effectivement analysé, après normalisation de la saisie.",
        "pourquoi": "Confirme la cible réelle : saisir www.exemple.com revient à analyser exemple.com, car c'est le domaine qui porte la réputation.",
    },
    "Enregistré": {
        "explication": "Indique si ce nom de domaine existe réellement dans le registre officiel, avec le code de réponse obtenu.",
        "pourquoi": "Un domaine cité dans un courriel ou une alerte mais inconnu du registre est une anomalie forte : il a été retiré, n'a jamais été enregistré, ou la saisie est fautive. Aucune réputation ne peut être établie sur un domaine qui n'existe pas.",
    },
    "Registrar": {
        "explication": "Bureau d'enregistrement chez qui le domaine a été réservé.",
        "pourquoi": "Certains bureaux concentrent les dépôts anonymes et à bas coût, ce qui rend le domaine plus jetable donc plus suspect.",
    },
    "Créé le": {
        "explication": "Date à laquelle le domaine a été réservé pour la première fois auprès du registre.",
        "pourquoi": "C'est la donnée la plus parlante sur un domaine : les campagnes d'hameçonnage utilisent des domaines de quelques jours.",
    },
    "Expire le": {
        "explication": "Date à laquelle l'enregistrement devra être renouvelé.",
        "pourquoi": "Une échéance très proche sur un domaine actif peut annoncer un abandon ou une opération de courte durée.",
    },
    "Âge": {
        "explication": "Nombre de jours écoulés depuis la création du domaine.",
        "pourquoi": "Moins de trente jours est fortement suspect ; plusieurs années est rassurant, sans être une garantie : un domaine ancien peut être détourné après une compromission.",
    },
    "Serveurs de noms": {
        "explication": "Serveurs qui détiennent les informations de résolution du domaine. Deux serveurs au minimum sont requis par les règles de l'Internet.",
        "pourquoi": "Un serveur unique signale un domaine préparé à la hâte, sans le soin qu'apporte un site réellement exploité.",
    },
    "Statut registre": {
        "explication": "État officiel du domaine auprès du registre : actif, en attente, suspendu, transfert bloqué…",
        "pourquoi": "Un statut de suspension signifie que le registre a retiré le domaine de la circulation, très souvent pour abus constatés.",
    },
    "Adresse IP": {
        "explication": "Adresse vers laquelle le nom de domaine se résout actuellement.",
        "pourquoi": "Permet de relier un nom à une infrastructure : plusieurs domaines malveillants partagent souvent la même adresse.",
    },

    # --- Sécurité du courrier électronique ---
    "SPF": {
        "explication": "Enregistrement qui déclare la liste des serveurs autorisés à envoyer du courrier au nom de ce domaine.",
        "pourquoi": "Sans lui, n'importe qui peut se faire passer pour ce domaine par courriel. Son absence est un signe de négligence, voire de préparation d'usurpation.",
    },
    "DMARC": {
        "explication": "Politique qui indique à votre messagerie quoi faire d'un courrier usurpant ce domaine : le surveiller, le mettre en quarantaine ou le rejeter.",
        "pourquoi": "C'est la protection la plus efficace contre l'usurpation par courriel. Une politique stricte (« p=reject ») rend l'usurpation inopérante, et son absence laisse la porte ouverte.",
    },
    "Serveurs mail (MX)": {
        "explication": "Serveurs qui reçoivent le courrier destiné à ce domaine.",
        "pourquoi": "Un domaine qui reçoit du courrier se veut crédible. Un domaine sans serveur de courrier peut être purement décoratif, ou réservé à l'usurpation d'envoi.",
    },

    # --- Empreintes de fichiers ---
    "Empreinte": {
        "explication": "Signature calculée à partir du contenu du fichier : deux fichiers identiques ont la même empreinte, et un fichier modifié d'un seul octet en change complètement.",
        "pourquoi": "Permet d'identifier un fichier sans le posséder ni l'exécuter. C'est le moyen sûr de vérifier si un fichier est connu comme malveillant.",
    },
    "Algorithme": {
        "explication": "Fonction ayant produit l'empreinte, déduite de sa longueur : 32 caractères pour MD5, 40 pour SHA-1, 64 pour SHA-256.",
        "pourquoi": "L'outil déduit le type sans que l'utilisateur ait à le préciser, ce qui évite une erreur de saisie.",
    },
    "Nom du fichier": {
        "explication": "Nom sous lequel ce fichier a été catalogué par la base publique.",
        "pourquoi": "Confirme l'identification : un fichier présenté comme une photo mais catalogué comme programme est un signal fort.",
    },
    "Taille": {
        "explication": "Taille du fichier exprimée en octets, telle que la connaît la base publique.",
        "pourquoi": "Permet de repérer une anomalie : une pièce jointe annoncée comme document mais pesant plusieurs mégaoctets mérite un contrôle.",
    },
    "Produit": {
        "explication": "Programme auquel ce fichier appartient lorsqu'il est connu comme légitime.",
        "pourquoi": "Un fichier rattaché à un éditeur connu est probablement sain ; un fichier inconnu ne dit rien, ni bon ni mauvais.",
    },
    "Éditeur": {
        "explication": "Entité ayant signé ou publié le fichier, quand elle est connue.",
        "pourquoi": "Confirme l'origine d'un fichier légitime, ou trahit une usurpation si l'éditeur affiché ne correspond pas à l'usage annoncé.",
    },
    "Indice de confiance": {
        "explication": "De 0 à 100, le degré de fiabilité attribué au fichier par la base publique : plus il est haut, plus le fichier est reconnu comme sûrement légitime.",
        "pourquoi": "Attention au contresens : un indice bas sur un fichier connu signale un fichier souvent signalé comme malveillant, et non un fichier anodin.",
    },
    "Connue des bases publiques": {
        "explication": "Indique si cette empreinte est déjà répertoriée dans la base publique de référence des fichiers connus.",
        "pourquoi": "Une empreinte inconnue ne veut pas dire fichier sain, ni fichier malveillant : elle signifie que ce contenu n'a jamais été catalogué. Un programme développé en interne tombe dans ce cas.",
    },
}

# ---------------------------------------------------------------------------
# 2) LES SIGNAUX QUI PÈSENT DANS LE SCORE
#
# La correspondance se fait sur le début du libellé : les libellés contiennent
# des valeurs variables (un score, un nombre de jours, un pays), donc une
# comparaison exacte serait impossible à maintenir. Un test garantit que tout
# libellé produit par l'outil trouve bien son explication.
# ---------------------------------------------------------------------------

SIGNAUX = [
    # (début du libellé, explication, pourquoi)
    (
        "Score d'abus AbuseIPDB très élevé",
        "La communauté des administrateurs a classé cette adresse parmi les plus hostiles.",
        "Un score très élevé repose sur des signalements indépendants et concordants : c'est le signal le plus solide disponible sur une adresse IP.",
    ),
    (
        "Score d'abus AbuseIPDB modéré",
        "Des abus ont été rapportés sur cette adresse, sans atteindre le niveau des adresses les plus hostiles.",
        "Signale une adresse à surveiller, pas encore une source d'attaque confirmée.",
    ),
    (
        "signalements d'abus recensés",
        "Plusieurs administrateurs ont rapporté cette adresse comme source d'abus.",
        "Des signalements répétés venant de réseaux différents ne s'expliquent pas par un faux positif.",
    ),
    (
        "Adresse présente sur la liste blanche",
        "Cette adresse fait partie de celles qu'AbuseIPDB ne signale jamais.",
        "C'est le seul signal qui fait baisser le score : il traduit une réputation durablement bonne, pas seulement l'absence d'abus signalé.",
    ),
    (
        "Adresse hébergée dans un datacenter",
        "L'adresse appartient à un centre de données ou à un hébergeur professionnel.",
        "Signal faible, et volontairement pondéré comme tel : les serveurs de noms publics, les CDN et tous les services en nuage sont en centre de données. Il compte en combinaison avec d'autres, jamais seul.",
    ),
    (
        "Adresse détectée comme proxy",
        "Le trafic provenant de cette adresse passe par un service qui masque son origine : réseau privé virtuel, proxy commercial ou nœud Tor.",
        "L'anonymat volontaire ne prouve pas la malveillance, mais il complique l'attribution et mérite une surveillance.",
    ),
    (
        "réseau mobile",
        "L'adresse appartient à un opérateur de téléphonie mobile.",
        "Une adresse mobile est partagée par des milliers d'abonnés : elle est presque toujours un faux positif. C'est pourquoi ce signal ne vaut que 5 points.",
    ),
    (
        "ne se résout pas en adresse IP",
        "Le nom de domaine ne renvoie vers aucune adresse : il n'est relié à aucun serveur.",
        "Un domaine actif qui ne résout pas est inhabituel. Cela traduit souvent un domaine réservé à l'avance, ou dont l'hébergement vient d'être démonté après une campagne.",
    ),
    (
        "inconnu du registre",
        "Le registre officiel ne connaît pas ce domaine : il n'est pas enregistré, ou son enregistrement a expiré.",
        "Un domaine utilisable dans un message sans exister au registre est une anomalie forte, typique d'une usurpation ou d'une saisie erronée.",
    ),
    (
        "enregistré récemment",
        "Ce domaine a été créé il y a très peu de temps.",
        "C'est la signature la plus courante des campagnes d'hameçonnage : un domaine neuf, utilisé puis abandonné avant d'être signalé.",
    ),
    (
        "Domaine récent",
        "Ce domaine existe depuis peu de temps, sans être tout neuf pour autant.",
        "Un domaine jeune n'a pas encore pu se construire une réputation. C'est un facteur de méfiance, sans preuve de malveillance.",
    ),
    (
        "Domaine ancien",
        "Ce domaine existe depuis longtemps et a donc eu le temps de bâtir une réputation.",
        "Un domaine durablement exploité a peu de chances d'être un domaine jetable. L'ancienneté rassure, sans garantir : un site abandonné peut être détourné.",
    ),
    (
        "suspendu par le registre",
        "Le registre a retiré ce domaine de la circulation, ou l'a gelé.",
        "Cette décision est presque toujours prise après constat d'abus. C'est un signal fort, émanant d'une autorité et non d'une opinion.",
    ),
    (
        "Un seul serveur de noms",
        "Le domaine ne déclare qu'un seul serveur de noms.",
        "Les règles de l'Internet en exigent au moins deux, pour la disponibilité. Un serveur unique trahit une mise en place hâtive, sans le soin d'un service réellement exploité.",
    ),
    (
        "Aucun enregistrement SPF",
        "Ce domaine ne déclare pas quels serveurs peuvent envoyer du courrier en son nom.",
        "Sans cette déclaration, n'importe qui peut usurper le domaine par courriel : c'est une porte ouverte à l'hameçonnage.",
    ),
    (
        "Aucune politique DMARC",
        "Ce domaine n'indique pas quoi faire d'un courrier qui l'usurpe.",
        "Sans politique, votre messagerie ne peut pas rejeter automatiquement les messages frauduleux utilisant ce domaine.",
    ),
    (
        "Politique DMARC stricte",
        "Ce domaine a choisi de faire rejeter tout courrier usurpant son nom.",
        "Choix protecteur : l'usurpation devient inopérante. C'est le seul signal de courrier qui fait baisser le score.",
    ),
    (
        "reçoit du courrier mais ne publie aucune politique DMARC",
        "Ce domaine reçoit du courrier, mais ne protège pas son nom contre l'usurpation.",
        "Domaine réellement utilisé pour communiquer, donc crédible pour un destinataire, mais sans défense : c'est la cible idéale d'une usurpation.",
    ),
    (
        "Empreinte inconnue de la base publique",
        "Ce fichier n'est répertorié par aucune base publique.",
        "Un fichier inconnu n'est ni sain ni malveillant : il est simplement non catalogué. Un fichier récent ou rare tombe dans ce cas, comme un programme maison.",
    ),
    (
        "Fichier connu et fiable",
        "Ce fichier est identifié comme appartenant à un programme légitime et reconnu.",
        "C'est le signal le plus rassurant possible sur une empreinte : le contenu exact du fichier a déjà été vérifié et catalogué.",
    ),
    (
        "Fichier connu mais peu fiable",
        "Ce fichier est répertorié, mais souvent signalé comme indésirable ou malveillant.",
        "Contrairement à l'intuition, être connu n'est pas rassurant : c'est la fréquence des signalements qui compte, et elle est ici mauvaise.",
    ),
    (
        "Infrastructure localisée en",
        "L'opérateur de cette adresse est situé dans un pays où les rapports publics de menace relèvent statistiquement plus d'infrastructures malveillantes.",
        "Signal volontairement faible, à 10 points, et jamais décisif seul : un pays n'est pas une preuve, et cette statistique ne dit rien d'une adresse particulière. Elle invite seulement à regarder de plus près.",
    ),
    (
        "Extension de domaine",
        "Cette extension de domaine est bon marché ou gratuite, et très utilisée par les campagnes d'hameçonnage.",
        "Le coût dérisoire permet d'enregistrer des centaines de domaines jetables. Cela ne rend pas ce domaine-ci malveillant, mais augmente la probabilité.",
    ),
]

# Raisons rédigées directement par le moteur, hors signaux.
RAISONS_SPECIALES = {
    "Aucun signal négatif détecté":
        "Aucune des sources interrogées n'a rapporté d'élément défavorable sur cet indicateur.",
    "Adresse interne au réseau":
        "Une adresse interne n'existe que dans votre réseau : sa vérification se fait dans votre inventaire et vos journaux, jamais dans une base publique.",
    "Aucune base de renseignement publique ne peut se prononcer":
        "Les bases publiques ne connaissent que les adresses visibles depuis Internet. Interroger l'une d'elles pour une adresse privée ne renverrait rien d'exploitable.",
    "Adresse non routable":
        "Cette adresse appartient à une plage réservée à un usage interne : elle ne circule jamais sur Internet public.",
    "Adresse privée":
        "Cette adresse appartient à une plage réservée aux réseaux internes, définie par le document RFC 1918.",
    "locale":
        "Cette adresse désigne la machine elle-même. Elle n'a de sens que sur la machine qui l'utilise.",
    "lien-local":
        "Cette adresse est auto-attribuée par une machine qui n'a pas obtenu d'adresse auprès du réseau.",
    "multicast":
        "Cette adresse désigne un groupe de machines, jamais une machine en particulier.",
    "non spécifiée":
        "Cette adresse est la valeur nulle : elle ne désigne aucun hôte.",
    "réservée":
        "Cette adresse appartient à une plage réservée par l'autorité qui gère l'adressage mondial, hors usage courant.",
}

# ---------------------------------------------------------------------------
# 3) LE VOCABULAIRE, POUR LE GLOSSAIRE
# ---------------------------------------------------------------------------

CONCEPTS = [
    {
        "terme": "Indicateur de compromission",
        "categorie": "Notions",
        "explication": "Élément technique qui peut révéler une intrusion : adresse IP, nom de domaine, empreinte de fichier, ou encore une clé de registre.",
        "en_pratique": "Un indicateur n'est jamais une preuve à lui seul. C'est un point de départ : il devient utile confronté à d'autres observations.",
    },
    {
        "terme": "Renseignement sur les menaces",
        "categorie": "Notions",
        "explication": "Démarche consistant à rassembler des informations publiques sur un indicateur pour décider de la conduite à tenir.",
        "en_pratique": "L'outil automatise la collecte et la synthèse, mais la décision reste à l'analyste : un score ne remplace pas un jugement.",
    },
    {
        "terme": "Score de risque",
        "categorie": "Notions",
        "explication": "Note de 0 à 100 obtenue en additionnant des signaux pondérés, à partir d'un score de départ de 10.",
        "en_pratique": "Le score sert à comparer et à prioriser, pas à trancher. Deux indicateurs à 40 ne sont pas dangereux de la même façon.",
    },
    {
        "terme": "Niveau de risque",
        "categorie": "Notions",
        "explication": "Traduction du score en quatre paliers : SAIN jusqu'à 24, DOUTEUX de 25 à 49, SUSPECT de 50 à 74, MALVEILLANT à partir de 75.",
        "en_pratique": "Le seuil intermédiaire est placé à 25 pour qu'aucun signal faible isolé ne suffise à faire basculer un verdict.",
    },
    {
        "terme": "Signal",
        "categorie": "Notions",
        "explication": "Élément observé qui pèse dans le score, à la hausse ou à la baisse, avec un nombre de points défini.",
        "en_pratique": "Chaque signal est affiché avec sa valeur et son explication : le score reste vérifiable, jamais une boîte noire.",
    },
    {
        "terme": "Adresse IP",
        "categorie": "Réseau",
        "explication": "Numéro identifiant une machine sur un réseau. La version 4 s'écrit en quatre blocs de 0 à 255, la version 6 en hexadécimal séparé par des deux-points.",
        "en_pratique": "Une adresse IP ne désigne pas toujours une machine : elle peut désigner une infrastructure partagée qui sert des milliers de clients.",
    },
    {
        "terme": "ASN — numéro de système autonome",
        "categorie": "Réseau",
        "explication": "Numéro identifiant l'opérateur chargé d'annoncer un bloc d'adresses auprès du reste d'Internet.",
        "en_pratique": "Le meilleur point d'entrée pour regrouper des adresses : un même opérateur héberge souvent toute une campagne.",
    },
    {
        "terme": "Bloc d'adresses",
        "categorie": "Réseau",
        "explication": "Plage continue d'adresses attribuée d'un seul tenant à un opérateur ou à une organisation.",
        "en_pratique": "Quand une adresse est identifiée comme hostile, c'est souvent son voisinage qui l'est aussi. La plage donne le périmètre à surveiller.",
    },
    {
        "terme": "DNS inverse",
        "categorie": "Réseau",
        "explication": "Correspondance entre une adresse et un nom, dans l'autre sens que la résolution habituelle. La zone inverse est « in-addr.arpa » pour la version 4 et « ip6.arpa » pour la version 6.",
        "en_pratique": "Un nom inverse bien renseigné révèle l'usage réel d'une adresse, ce que les seules coordonnées géographiques ne disent pas.",
    },
    {
        "terme": "Centre de données",
        "categorie": "Réseau",
        "explication": "Bâtiment où sont hébergés des serveurs loués à l'heure ou au mois.",
        "en_pratique": "La majorité des serveurs malveillants y sont loués. Mais les serveurs de noms publics et les CDN y sont aussi, d'où la pondération volontairement faible de ce signal.",
    },
    {
        "terme": "CDN — réseau de diffusion de contenu",
        "categorie": "Réseau",
        "explication": "Ensemble de serveurs répartis dans le monde qui servent un même contenu depuis le point le plus proche de l'utilisateur.",
        "en_pratique": "Une adresse de CDN est partagée par des milliers de sites. Bloquer l'adresse revient à bloquer tout le monde, y compris des sites légitimes : c'est le nom d'hôte qu'il faut bloquer.",
    },
    {
        "terme": "Proxy et réseau privé virtuel",
        "categorie": "Réseau",
        "explication": "Service qui relaie le trafic pour masquer l'adresse réelle de son auteur.",
        "en_pratique": "L'anonymat volontaire gêne l'attribution sans prouver la malveillance. Un utilisateur légitime peut parfaitement s'en servir.",
    },
    {
        "terme": "Tor",
        "categorie": "Réseau",
        "explication": "Réseau d'anonymisation qui fait passer le trafic par plusieurs relais successifs. Le dernier, appelé nœud de sortie, est celui que voit le site visité.",
        "en_pratique": "Une attaque attribuée à un nœud de sortie peut venir de n'importe quel utilisateur du réseau. La conclusion « cette machine attaque » serait alors fausse.",
    },
    {
        "terme": "Adresse privée",
        "categorie": "Adressage",
        "explication": "Adresse réservée aux réseaux internes, définie par le document RFC 1918 : 10.0.0.0/8, 172.16.0.0/12 et 192.168.0.0/16.",
        "en_pratique": "Elle ne circule jamais sur Internet public. Chercher sa réputation en ligne n'a aucun sens : la réponse se trouve dans l'inventaire du parc.",
    },
    {
        "terme": "Adresse de boucle locale",
        "categorie": "Adressage",
        "explication": "Adresse par laquelle une machine se désigne elle-même : 127.0.0.1 en version 4, ::1 en version 6.",
        "en_pratique": "Utilisée pour tester un service local sans passer par le réseau.",
    },
    {
        "terme": "Adresse lien-local",
        "categorie": "Adressage",
        "explication": "Adresse attribuée automatiquement par une machine qui n'a pas obtenu d'adresse auprès du réseau : 169.254.0.0/16 en version 4, fe80::/10 en version 6.",
        "en_pratique": "Sa présence dans un journal signale souvent un problème de configuration, pas une attaque.",
    },
    {
        "terme": "Adresse multicast",
        "categorie": "Adressage",
        "explication": "Adresse désignant un groupe de machines, et non une machine en particulier.",
        "en_pratique": "Les plages de diffusion de groupe ne peuvent pas être interrogées comme une machine : elles ne désignent personne.",
    },
    {
        "terme": "Nom de domaine",
        "categorie": "Noms",
        "explication": "Nom lisible par un humain, associé à des adresses par le système de noms de domaine.",
        "en_pratique": "C'est le domaine qui porte la réputation, pas ses sous-domaines : analyser www.exemple.com revient à analyser exemple.com.",
    },
    {
        "terme": "Extension de domaine",
        "categorie": "Noms",
        "explication": "Dernière partie d'un nom de domaine : .com, .ci, .org, .xyz…",
        "en_pratique": "Certaines extensions sont gratuites ou presque, ce qui permet d'enregistrer des domaines jetables par centaines. C'est un facteur de méfiance, pas une preuve.",
    },
    {
        "terme": "Registrar",
        "categorie": "Noms",
        "explication": "Bureau d'enregistrement accrédité chez qui un domaine est réservé.",
        "en_pratique": "Les bureaux peu regardants attirent les dépôts anonymes : le nom du registrar fait partie du faisceau d'indices.",
    },
    {
        "terme": "RDAP — protocole d'accès aux données d'enregistrement",
        "categorie": "Noms",
        "explication": "Successeur moderne du service d'annuaire « whois ». Il interroge les registres régionaux pour obtenir le titulaire, les dates et le statut d'un domaine ou d'un bloc d'adresses.",
        "en_pratique": "Réponse « 404 » signifie que le registre ne connaît pas l'objet demandé : le domaine n'est pas enregistré, ce qui est en soi une anomalie.",
    },
    {
        "terme": "SPF — expéditeurs autorisés",
        "categorie": "Courriel",
        "explication": "Enregistrement qui déclare officiellement quels serveurs ont le droit d'envoyer du courrier au nom du domaine.",
        "en_pratique": "Sans lui, l'usurpation est triviale. Sa présence ne protège pas complètement, mais son absence est une faiblesse certaine.",
    },
    {
        "terme": "DMARC — politique de traitement de l'usurpation",
        "categorie": "Courriel",
        "explication": "Enregistrement qui indique au destinataire quoi faire d'un courrier usurpant le domaine : ne rien faire, mettre en quarantaine, ou rejeter.",
        "en_pratique": "C'est la protection la plus efficace contre l'hameçonnage par usurpation. La valeur « p=reject » fait bloquer toute usurpation.",
    },
    {
        "terme": "MX — serveurs de courrier",
        "categorie": "Courriel",
        "explication": "Serveurs chargés de recevoir le courrier destiné à un domaine.",
        "en_pratique": "Un domaine qui reçoit du courrier mais ne publie aucune politique anti-usurpation combine crédibilité et vulnérabilité.",
    },
    {
        "terme": "Empreinte de fichier",
        "categorie": "Fichiers",
        "explication": "Signature calculée à partir du contenu d'un fichier. Modifier un seul octet change l'empreinte entièrement.",
        "en_pratique": "Elle permet de vérifier si un fichier est déjà connu sans jamais l'ouvrir ni l'exécuter : c'est la méthode la plus sûre.",
    },
    {
        "terme": "MD5, SHA-1, SHA-256",
        "categorie": "Fichiers",
        "explication": "Trois fonctions produisant des empreintes de longueurs différentes : 32, 40 et 64 caractères hexadécimaux.",
        "en_pratique": "MD5 et SHA-1 ne sont plus fiables pour la sécurité, mais restent les identifiants employés par les bases publiques de fichiers malveillants.",
    },
    {
        "terme": "Leetspeak",
        "categorie": "Fichiers",
        "explication": "Écriture consistant à remplacer des lettres par des chiffres ou des symboles, par exemple « p4ssw0rd » pour « password ».",
        "en_pratique": "L'outil la repère en local : un mot de passe ainsi déguisé est reconnu comme mot de passe courant et déclaré faible.",
    },
    {
        "terme": "IOC désamorcé",
        "categorie": "Bonnes pratiques",
        "explication": "Indicateur rendu inoffensif avant publication dans un rapport, en neutralisant son lien : 185[.]10[.]10[.]5 au lieu de 185.10.10.5, ou hxxp au lieu de http.",
        "en_pratique": "Cela évite qu'un clic accidentel dans un rapport n'ouvre le lien hostile. L'outil reconnaît cette écriture et rétablit automatiquement la forme exploitable.",
    },
    {
        "terme": "Faux positif",
        "categorie": "Bonnes pratiques",
        "explication": "Indicateur déclaré dangereux à tort, alors qu'il appartient en réalité à un service légitime.",
        "en_pratique": "C'est le risque principal de tout outil de notation : bloquer un service légitime coûte souvent plus cher que laisser passer une menace. C'est pourquoi les signaux faibles sont pondérés bas.",
    },
    {
        "terme": "Indicateur exploitable",
        "categorie": "Bonnes pratiques",
        "explication": "Indicateur dont le blocage est réellement utile, sans effet secondaire disproportionné.",
        "en_pratique": "Une adresse de CDN n'est pas un indicateur exploitable : bloquer l'adresse reviendrait à couper tous les sites qui la partagent. C'est le nom d'hôte qui doit être bloqué.",
    },
    {
        "terme": "Durée de vie d'un indicateur",
        "categorie": "Bonnes pratiques",
        "explication": "Temps pendant lequel un indicateur reste pertinent. Elle est courte : une adresse louée à l'heure change d'affectation en quelques jours.",
        "en_pratique": "Un indicateur vieux de plusieurs mois a de bonnes chances d'être périmé, et donc de faire bloquer une victime plutôt qu'un attaquant.",
    },
]


# ---------------------------------------------------------------------------
# 4) FONCTIONS D'ACCÈS
# ---------------------------------------------------------------------------


def explication_champ(libelle: str) -> dict:
    """Retourne l'explication d'une information brute, ou un repli explicite.

    Le repli n'est pas silencieux : il indique clairement qu'aucune explication
    n'a été rédigée pour ce champ. Un contrôle automatique empêche ce cas.
    """
    return CHAMPS.get(libelle, {
        "explication": "Aucune explication rédigée pour cette information.",
        "pourquoi": "",
    })


def expliquer_champs(fields) -> list[dict]:
    """Transforme une liste de couples (libellé, valeur) en informations expliquées.

    Chaque entrée devient un dictionnaire portant le libellé, la valeur, et les
    deux niveaux d'explication. Les gabarits et l'API consomment cette forme.
    """
    expliques = []
    for field in fields or []:
        libelle, valeur = field[0], field[1]
        explication = explication_champ(libelle)
        expliques.append({
            "libelle": libelle,
            "valeur": valeur,
            "explication": explication["explication"],
            "pourquoi": explication["pourquoi"],
        })
    return expliques


def explication_signal(libelle: str):
    """Retourne l'explication d'un signal, en cherchant un fragment connu.

    La recherche se fait par inclusion et non par égalité : les libellés portent
    des valeurs variables (un score, un nombre de jours, un pays) et un nombre
    peut même les précéder. Une comparaison exacte serait intenable.

    L'ordre de la table compte : les fragments les plus précis sont placés en
    premier, sinon un fragment court masquerait un fragment long qui le contient.
    """
    for debut, explication, pourquoi in SIGNAUX:
        if debut in libelle:
            return {"explication": explication, "pourquoi": pourquoi}
    for debut, explication in RAISONS_SPECIALES.items():
        if debut in libelle:
            return {"explication": explication, "pourquoi": ""}
    return None


def expliquer_signaux(signaux) -> list[dict]:
    """Ajoute à chaque signal son explication, ses points et sa contribution.

    `part` permet à l'écran de montrer comment le score total se construit :
    sans elle, l'analyste devrait additionner mentalement.
    """
    detailles = []
    for signal in signaux or []:
        libelle = signal.get("label", "")
        explication = explication_signal(libelle) or {
            "explication": "Aucune explication rédigée pour ce signal.",
            "pourquoi": "",
        }
        detailles.append({
            "label": libelle,
            "points": int(signal.get("points", 0)),
            "explication": explication["explication"],
            "pourquoi": explication["pourquoi"],
        })
    return detailles


def glossaire() -> list[dict]:
    """Retourne les concepts du glossaire, regroupés puis triés alphabétiquement.

    Le regroupement par catégorie donne une page lisible : on cherche un terme
    en sachant de quel domaine il relève.
    """
    categories: dict[str, list[dict]] = {}
    for concept in CONCEPTS:
        categories.setdefault(concept["categorie"], []).append(concept)
    return [
        {"categorie": categorie, "concepts": sorted(items, key=lambda c: c["terme"].lower())}
        for categorie, items in sorted(categories.items())
    ]


def nombre_explications() -> dict:
    """Compte les explications disponibles, pour l'afficher sur la page de glossaire."""
    return {
        "champs": len(CHAMPS),
        "signaux": len(SIGNAUX),
        "concepts": len(CONCEPTS),
    }
