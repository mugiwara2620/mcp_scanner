"""scanner.py — combine règles + juge LLM et rend un verdict par outil."""

from client import get_tools
from rules import check_rules
from judge import judge_tool  # adapte si c'est llm_judge dans ton repo


def _verdict(score: int, alertes: list) -> str:
    """Règle du README : score OU nombre d'alertes."""
    if score >= 7 or len(alertes) >= 2:
        return "dangereux"
    if score >= 4 or len(alertes) >= 1:
        return "suspect"
    return "sain"


def scan_outil(name: str, description: str) -> dict:
    """Scanne une description d'outil. Renvoie verdict + détails."""
    alertes = check_rules(description)

    # Juge LLM. Fail-closed : si l'appel échoue, on considère dangereux
    # plutôt que de laisser passer un outil non vérifié.
    try:
        v = judge_tool(name, description)   # -> objet avec .score et .reason
        score = v.score
        raison = v.reason
    except Exception as e:
        return {
            "name": name,
            "verdict": "dangereux",
            "score": None,
            "alertes": alertes,
            "raison": f"Juge indisponible, blocage par sécurité ({e})",
        }

    return {
        "name": name,
        "verdict": _verdict(score, alertes),
        "score": score,
        "alertes": alertes,
        "raison": raison,
    }


def scan(server_path: str) -> list:
    """Scanne tous les outils d'un serveur MCP. Renvoie un verdict par outil."""
    resultats = []
    for tool in get_tools(server_path):
        resultats.append(scan_outil(tool["name"], tool["description"]))
    return resultats


if __name__ == "__main__":
    import sys
    chemin = sys.argv[1] if len(sys.argv) > 1 else "attacks/evil_pii.py"
    print(f"Scan de {chemin}\n")
    for r in scan(chemin):
        print(f"  [{r['verdict'].upper()}] {r['name']}")
        print(f"    score juge : {r['score']}")
        print(f"    alertes règles : {r['alertes']}")
        print(f"    raison : {r['raison']}\n")