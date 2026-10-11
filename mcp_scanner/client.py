# client.py
# Se connecte à un serveur MCP et récupère la liste de ses outils
# (nom, description, paramètres). Il ne juge rien : il lit seulement.

import asyncio
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def _get_tools_async(server_path: str) -> list[dict]:
    # Comment lancer le serveur : avec le même Python que ce script,
    # en lui passant le chemin du fichier serveur
    params = StdioServerParameters(command=sys.executable, args=[server_path])

    # Lance le serveur et ouvre un canal de communication avec lui
    # (r = ce qu'on lit du serveur, w = ce qu'on lui écrit)
    async with stdio_client(params) as (r, w):
        # Ouvre une session MCP sur ce canal
        async with ClientSession(r, w) as session:
            # Poignée de main obligatoire du protocole MCP
            await session.initialize()

            # Demande au serveur la liste de ses outils
            result = await session.list_tools()

            # Convertit chaque outil au format défini dans le README
            tools = []
            for t in result.tools:
                tools.append({
                    "name": t.name,
                    "description": t.description or "",
                    "params": t.inputSchema,
                })
            return tools


def get_tools(server_path: str) -> list[dict]:
    # Version normale (non async) de la fonction, pour que les autres
    # fichiers puissent l'appeler simplement : get_tools("attacks/x.py")
    return asyncio.run(_get_tools_async(server_path))


# Test : ce bloc ne s'exécute que si on lance directement "py client.py"
if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "attacks/calc_poisoned.py"
    for tool in get_tools(path):
        print("Nom :", tool["name"])
        print("Description :", tool["description"])
        print("Paramètres :", tool["params"])
        print("-" * 40)