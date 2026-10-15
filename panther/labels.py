"""Libellés des types d'appareils, partagés par l'interface, les exports et les rapports (traduits à la lecture)."""
from .i18n import N_, TrDict

TYPE_LABELS = TrDict({"desktop": N_("Ordinateur"), "laptop": N_("Portable"), "phone": N_("Téléphone"),
                      "printer": N_("Imprimante"), "router": N_("Routeur / box"), "tv": N_("TV / multimédia"), "settop": N_("Décodeur TV"),
                      "tablet": N_("Tablette"), "console": N_("Console de jeux"), "speaker": N_("Enceinte connectée"),
                      "switch": N_("Switch"), "internet": N_("Internet"), "net": N_("Réseau"), "hop": N_("Routeur du chemin"),
                      "gap": N_("Saut sans réponse"), "camera": N_("Caméra"), "server": N_("Serveur"), "nas": N_("NAS"),
                      "iot": N_("Objet connecté"), "unknown": N_("Non identifié")})
