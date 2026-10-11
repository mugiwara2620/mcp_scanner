"""
demo.py — MCP_SCANNER end-to-end demo (Streamlit).

A security filter that sits between MCP servers and the agent. It reads each
tool's description, runs two detectors, and decides whether the tool is
forwarded to the agent, flagged, or dropped.

Pipeline (the repo's own pieces):
    fixtures.load_catalogue()          -> tools (name + description)
    scanner.scan_outil(name, desc)     -> {verdict, score, alertes, raison}
        (which itself calls rules.check_rules + judge.judge_tool and applies
         the README's combination rule, fail-closed)

Run:
    pip install -r requirements.txt
    # the judge uses AWS Bedrock — provide the usual AWS creds + a model id:
    export BEDROCK_MODEL_ID="..."      # or ANTHROPIC_DEFAULT_SONNET_MODEL
    streamlit run demo.py

Without creds / network the demo still runs: scanner.scan_outil() fails closed
(verdict "dangereux", score None) when the judge can't be reached, so nothing
unverified is ever cleared. That failure mode is itself part of the story.

Terminal fallback (no Streamlit needed):
    python demo.py --cli
"""

from __future__ import annotations

import sys
import time

from fixtures import load_catalogue

# French verdict strings produced by scanner._verdict().
DANGEROUS = "dangereux"
SUSPICIOUS = "suspect"
HEALTHY = "sain"


def _get_scan_outil():
    """Return scanner.scan_outil, resilient to optional-dependency import errors.

    scanner.py imports client.py at module load, which imports the `mcp` SDK.
    When that SDK isn't installed (e.g. a quick local run without the full
    stack), we rebuild the exact same combination (rules + judge, same rule,
    same fail-closed behaviour) so the demo still runs end-to-end.
    """
    try:
        from scanner import scan_outil  # teammate's real combined verdict
        return scan_outil
    except Exception:
        from rules import check_rules
        from judge import judge_tool  # judge import rarely fails (no mcp dep)

        def scan_outil(name: str, description: str) -> dict:
            alertes = check_rules(description)
            try:
                v = judge_tool(name, description)
                score, raison = v.score, v.reason
            except Exception as e:
                return {"name": name, "verdict": "dangereux", "score": None,
                        "alertes": alertes,
                        "raison": f"Juge indisponible, blocage par sécurité ({e})"}
            if score >= 7 or len(alertes) >= 2:
                verdict = "dangereux"
            elif score >= 4 or len(alertes) >= 1:
                verdict = "suspect"
            else:
                verdict = "sain"
            return {"name": name, "verdict": verdict, "score": score,
                    "alertes": alertes, "raison": raison}

        return scan_outil


scan_outil = _get_scan_outil()

LABEL = {
    DANGEROUS: ("Dangereux — retiré", "d"),
    SUSPICIOUS: ("Suspect — à revoir", "s"),
    HEALTHY: ("Sain — transmis", "h"),
}


# --------------------------------------------------------------------------
# Styling — restrained, minimal: near-black ink, generous whitespace, one
# accent, muted status tones. No gradients, no emoji, no rainbow colours.
# --------------------------------------------------------------------------
CSS = """
<style>
:root{
  --ink:#1a1a1a; --muted:#6b6b6b; --line:#e6e6e3; --paper:#ffffff; --soft:#faf9f7;
  --danger:#8a1c2b; --danger-bg:#f8eced; --danger-line:#e4c6ca;
  --warn:#6b5300;  --warn-bg:#f8f3e4;  --warn-line:#e4d8ad;
  --ok:#1f5134;    --ok-bg:#eef4ef;    --ok-line:#c6d8cb;
}
html,body,[class*="css"]{ font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Helvetica,Arial,sans-serif; }
.stApp{ background:var(--soft); color:var(--ink); }
#MainMenu,footer,header{ visibility:hidden; }
.block-container{ max-width:860px; padding-top:3rem; }

.kicker{ letter-spacing:.18em; text-transform:uppercase; font-size:.72rem; color:var(--muted); font-weight:600; }
.title{ font-size:2.2rem; font-weight:700; letter-spacing:-.02em; margin:.3rem 0 .4rem; }
.lede{ color:var(--muted); font-size:1.02rem; line-height:1.6; max-width:620px; }
.rule{ height:1px; background:var(--line); border:0; margin:1.6rem 0; }

.summary{ display:flex; gap:0; border:1px solid var(--line); border-radius:12px; overflow:hidden; background:var(--paper); }
.summary > div{ flex:1; padding:1.1rem 1rem; text-align:center; border-right:1px solid var(--line); }
.summary > div:last-child{ border-right:0; }
.summary .n{ font-size:1.7rem; font-weight:700; line-height:1; }
.summary .k{ font-size:.72rem; letter-spacing:.08em; text-transform:uppercase; color:var(--muted); margin-top:.45rem; }

.card{ background:var(--paper); border:1px solid var(--line); border-radius:12px; padding:1.1rem 1.25rem; margin-bottom:.8rem; }
.card.d{ border-left:3px solid var(--danger); }
.card.s{ border-left:3px solid var(--warn); }
.card.h{ border-left:3px solid var(--ok); }
.card .head{ display:flex; align-items:center; justify-content:space-between; gap:1rem; }
.toolname{ font-size:1.05rem; font-weight:650; }
.toolname .src{ color:var(--muted); font-weight:400; font-size:.85rem; margin-left:.5rem; }
.tag{ font-size:.72rem; font-weight:700; letter-spacing:.06em; text-transform:uppercase; padding:.3rem .7rem; border-radius:999px; white-space:nowrap; }
.tag.d{ color:var(--danger); background:var(--danger-bg); border:1px solid var(--danger-line); }
.tag.s{ color:var(--warn); background:var(--warn-bg); border:1px solid var(--warn-line); }
.tag.h{ color:var(--ok); background:var(--ok-bg); border:1px solid var(--ok-line); }

.meta{ display:flex; gap:1.6rem; margin-top:.9rem; font-size:.86rem; color:var(--muted); flex-wrap:wrap; }
.meta b{ color:var(--ink); font-weight:600; }
.desc{ margin-top:.8rem; font-size:.9rem; color:#333; background:var(--soft); border:1px solid var(--line);
       border-radius:9px; padding:.7rem .85rem; font-family:"SFMono-Regular",Menlo,Consolas,monospace; line-height:1.5; }
.reason{ margin-top:.7rem; font-size:.9rem; color:#333; line-height:1.55; }
.reason b{ color:var(--ink); }
.alerts span{ display:inline-block; font-size:.74rem; color:var(--danger); background:var(--danger-bg);
       border:1px solid var(--danger-line); border-radius:6px; padding:.12rem .5rem; margin:0 .3rem .3rem 0; }
.none{ color:var(--muted); font-size:.84rem; }
.note{ font-size:.86rem; color:var(--muted); border:1px dashed var(--line); border-radius:10px; padding:.8rem 1rem; background:var(--paper); }
</style>
"""


def esc(s) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def scan_all(catalogue):
    """Run the real scanner over every tool; return a list of result dicts."""
    results = []
    for tool in catalogue:
        r = scan_outil(tool["name"], tool["description"])
        # keep the source server for display
        r["server"] = tool.get("server", "")
        r["description"] = tool["description"]
        results.append(r)
    return results


def summary_bar(st, results):
    n_d = sum(1 for r in results if r["verdict"] == DANGEROUS)
    n_s = sum(1 for r in results if r["verdict"] == SUSPICIOUS)
    n_h = sum(1 for r in results if r["verdict"] == HEALTHY)
    st.markdown(
        f"""
        <div class="summary">
          <div><div class="n">{len(results)}</div><div class="k">Outils analysés</div></div>
          <div><div class="n" style="color:var(--danger)">{n_d}</div><div class="k">Retirés</div></div>
          <div><div class="n" style="color:var(--warn)">{n_s}</div><div class="k">À revoir</div></div>
          <div><div class="n" style="color:var(--ok)">{n_h}</div><div class="k">Transmis</div></div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_card(st, r, show_desc=True):
    label, cls = LABEL.get(r["verdict"], (r["verdict"], "s"))
    score = "—" if r.get("score") is None else f"{r['score']}/10"
    alertes = r.get("alertes") or []
    alerts_html = (
        "".join(f"<span>{esc(a)}</span>" for a in alertes)
        if alertes else '<span class="none">aucune alerte de règle</span>'
    )
    reason = esc(r.get("raison", "")) or "—"
    desc = r.get("description", "")
    if not show_desc:
        desc = desc[:90] + ("…" if len(desc) > 90 else "")
    st.markdown(
        f"""
        <div class="card {cls}">
          <div class="head">
            <div class="toolname">{esc(r['name'])}<span class="src">{esc(r.get('server',''))}</span></div>
            <div class="tag {cls}">{label}</div>
          </div>
          <div class="desc">{esc(desc)}</div>
          <div class="meta">
            <div>Score juge&nbsp;: <b>{score}</b></div>
            <div class="alerts">Règles&nbsp;: {alerts_html}</div>
          </div>
          <div class="reason"><b>Raison&nbsp;:</b> {reason}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _judge_available() -> bool:
    """Probe the judge once on a trivial description to see if it can run."""
    from judge import judge_tool, JudgeError
    try:
        judge_tool("probe", "Adds two numbers and returns the sum.")
        return True
    except Exception:
        return False


def run_cli() -> int:
    """Terminal fallback demo — works even where Streamlit isn't installed."""
    catalogue = load_catalogue(include_clean=True)
    print("\nMCP_SCANNER — filtre tool-poisoning (démo terminal)\n" + "=" * 54)
    results = scan_all(catalogue)
    order = {DANGEROUS: 0, SUSPICIOUS: 1, HEALTHY: 2}
    for r in sorted(results, key=lambda x: order.get(x["verdict"], 1)):
        label = LABEL.get(r["verdict"], (r["verdict"], ""))[0]
        score = "—" if r.get("score") is None else f"{r['score']}/10"
        alertes = ", ".join(r.get("alertes") or []) or "—"
        print(f"[{label:20}] {r['name']:24} score={score:6} règles={alertes}")
    n_d = sum(1 for r in results if r["verdict"] == DANGEROUS)
    n_s = sum(1 for r in results if r["verdict"] == SUSPICIOUS)
    n_h = sum(1 for r in results if r["verdict"] == HEALTHY)
    print("-" * 54)
    print(f"{len(results)} outils : {n_d} retirés, {n_s} à revoir, {n_h} transmis\n")
    return 0


def main():
    import streamlit as st  # imported here so the CLI fallback needs no Streamlit

    st.set_page_config(page_title="MCP_SCANNER", page_icon="▪", layout="centered")
    st.markdown(CSS, unsafe_allow_html=True)

    st.markdown('<div class="kicker">MCP_SCANNER</div>', unsafe_allow_html=True)
    st.markdown('<div class="title">Un filtre entre les serveurs MCP et l\'agent.</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="lede">Chaque outil annonce une description que l\'agent lit avant d\'agir. '
        'Un attaquant peut y cacher une instruction — c\'est le <i>tool poisoning</i>. '
        'Le filtre lit la même description, puis décide&nbsp;: la transmettre, la signaler, '
        'ou retirer le serveur sans que l\'agent le sache.</div>',
        unsafe_allow_html=True,
    )
    st.markdown('<hr class="rule"/>', unsafe_allow_html=True)

    catalogue = load_catalogue(include_clean=True)

    c1, c2 = st.columns([1, 1])
    with c1:
        run = st.button("Analyser les outils", type="primary", use_container_width=True)
    with c2:
        show_desc = st.toggle("Afficher les descriptions", value=True)

    if not _judge_available():
        st.markdown(
            '<div class="note">Juge LLM indisponible dans cet environnement '
            '(credentials AWS / modèle Bedrock manquants, ou hors-ligne). '
            'Le scanner <b>échoue en fermeture</b>&nbsp;: tout outil non vérifié est classé '
            '« dangereux » par sécurité. Avec le juge configuré, les pièges subtils sont '
            'départagés et les outils sains passent.</div>',
            unsafe_allow_html=True,
        )

    st.write("")

    if not run:
        st.markdown(
            f'<div class="none">{len(catalogue)} outils chargés '
            f'({sum(1 for t in catalogue if t["attack_class"])} piégés, '
            f'{sum(1 for t in catalogue if not t["attack_class"])} sains). '
            'Cliquez sur « Analyser les outils » pour lancer le filtre.</div>',
            unsafe_allow_html=True,
        )
        return

    progress = st.progress(0.0, text="Analyse des descriptions…")
    results = []
    for i, tool in enumerate(catalogue, start=1):
        r = scan_outil(tool["name"], tool["description"])
        r["server"] = tool.get("server", "")
        r["description"] = tool["description"]
        results.append(r)
        progress.progress(i / len(catalogue), text=f"Analysé {i}/{len(catalogue)}")
        time.sleep(0.05)
    progress.empty()

    summary_bar(st, results)
    st.markdown('<hr class="rule"/>', unsafe_allow_html=True)

    order = {DANGEROUS: 0, SUSPICIOUS: 1, HEALTHY: 2}
    for r in sorted(results, key=lambda x: order.get(x["verdict"], 1)):
        render_card(st, r, show_desc=show_desc)


if __name__ == "__main__":
    if "--cli" in sys.argv:
        raise SystemExit(run_cli())
    try:
        import streamlit  # noqa: F401
    except Exception:
        print("(Streamlit non installé — bascule sur la démo terminal)\n")
        raise SystemExit(run_cli())
    try:
        from streamlit.runtime.scriptrunner import get_script_run_ctx
        if get_script_run_ctx() is None:
            print("Astuce : lancez `streamlit run demo.py` pour l'interface web.\n"
                  "Démo terminal en attendant :\n")
            raise SystemExit(run_cli())
    except SystemExit:
        raise
    except Exception:
        pass
    main()
