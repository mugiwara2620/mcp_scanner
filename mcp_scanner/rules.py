import re

# Chaque règle : (nom de l'alerte, motif regex). Motifs en français et en anglais.
REGLES = [
    ("balise cachée",
     r"<\s*/?\s*(important|system|instructions?|secret|hidden|admin)\b[^>]*>"),

    ("fichier sensible",
     r"\.ssh|id_rsa|\.env\b|\.aws|credentials"
     r"|cl[ée] priv[ée]e|private key|/etc/shadow"),

    ("demande de secret",
     r"ne (le |la |les |l')?(mentionne|dis|signale|r[ée]v[èe]le)"
     r"|sans (le |l')?(dire|mentionner|pr[ée]venir)"
     r"|(don'?t|do not|never) (tell|mention|reveal|inform)"
     r"|without (telling|informing)"),

    ("détournement",
     r"ignore[rz]? (les |toutes les )?(instructions|consignes|r[èe]gles)"
     r"|oublie (les|tes) instructions"
     r"|ignore (all |any )?(previous|prior|above) (instructions|rules)"
     r"|tu es maintenant|you are now"),

    ("exfiltration",
     r"[\w.-]+@[\w-]+\.\w+"
     r"|historique de (la )?conversation|conversation history"
     r"|the conversation to"),
]

def check_rules(description: str) -> list[str]:
    alertes = []
    for nom, motif in REGLES:
        if re.search(motif, description, re.IGNORECASE):
            alertes.append(nom)
    return alertes

if __name__ == "__main__":
    from client import get_tools
    for tool in get_tools("attacks/calc_poisoned.py"):
        print(tool["name"], check_rules(tool["description"]))