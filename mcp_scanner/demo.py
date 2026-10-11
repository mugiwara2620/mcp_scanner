"""
demo.py — MCP_SCANNER end-to-end demo (Streamlit & CLI).

A security filter that sits between MCP servers and the AI agent. It inspects
each tool's description before the agent reads it, runs two complementary
detectors (deterministic rules + LLM judge), and decides whether each tool is
forwarded to the agent, flagged, or silently dropped.
"""

from __future__ import annotations

import sys
import time
from dotenv import load_dotenv

load_dotenv(override=True)

from fixtures import load_catalogue

# French verdict strings produced by scanner._verdict().
DANGEROUS = "dangereux"
SUSPICIOUS = "suspect"
HEALTHY = "sain"


def _get_scan_outil():
    """Return scanner.scan_outil, resilient to optional-dependency import errors."""
    try:
        from scanner import scan_outil
        return scan_outil
    except Exception:
        from rules import check_rules
        from judge import judge_tool

        def scan_outil(name: str, description: str) -> dict:
            alertes = check_rules(description)
            try:
                v = judge_tool(name, description)
                score, raison = v.score, v.reason
            except Exception as e:
                return {
                    "name": name,
                    "verdict": "dangereux",
                    "score": None,
                    "alertes": alertes,
                    "raison": f"Juge indisponible, blocage par sécurité ({e})",
                }
            if score >= 7 or len(alertes) >= 2:
                verdict = "dangereux"
            elif score >= 4 or len(alertes) >= 1:
                verdict = "suspect"
            else:
                verdict = "sain"
            return {
                "name": name,
                "verdict": verdict,
                "score": score,
                "alertes": alertes,
                "raison": raison,
            }

        return scan_outil


scan_outil = _get_scan_outil()

LABEL = {
    DANGEROUS: ("Dangereux — retiré", "d"),
    SUSPICIOUS: ("Suspect — à revoir", "s"),
    HEALTHY: ("Sain — transmis", "h"),
}

# --------------------------------------------------------------------------
# Modern Cybersecurity UI Design System with Dynamic Visual Effects
# --------------------------------------------------------------------------
CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

:root {
  --bg-main: #0A0E17;
  --bg-card: #111726;
  --bg-card-hover: #151D30;
  --bg-inner: #060911;
  --border-subtle: rgba(255, 255, 255, 0.08);
  --border-card: rgba(255, 255, 255, 0.12);
  --text-main: #F8FAFC;
  --text-muted: #94A3B8;
  --text-dim: #64748B;

  --danger-color: #EF4444;
  --danger-glow: rgba(239, 68, 68, 0.15);
  --danger-border: rgba(239, 68, 68, 0.35);
  --danger-tag: #FCA5A5;

  --warn-color: #F59E0B;
  --warn-glow: rgba(245, 158, 11, 0.15);
  --warn-border: rgba(245, 158, 11, 0.35);
  --warn-tag: #FCD34D;

  --ok-color: #10B981;
  --ok-glow: rgba(16, 185, 129, 0.15);
  --ok-border: rgba(16, 185, 129, 0.35);
  --ok-tag: #6EE7B7;
}

html, body, [class*="css"], .stApp {
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  background-color: var(--bg-main) !important;
  color: var(--text-main) !important;
}

#MainMenu, footer, header {
  visibility: hidden;
  height: 0px;
}

.block-container {
  max-width: 980px !important;
  padding-top: 2rem !important;
  padding-bottom: 3.5rem !important;
}

/* Animations */
@keyframes haloPulse {
  0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.5); }
  70% { transform: scale(1.05); box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }
  100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
}

@keyframes logoShine {
  0% { filter: drop-shadow(0 0 10px rgba(99, 102, 241, 0.3)); }
  50% { filter: drop-shadow(0 0 25px rgba(99, 102, 241, 0.65)); }
  100% { filter: drop-shadow(0 0 10px rgba(99, 102, 241, 0.3)); }
}

@keyframes beamFlow {
  0% { background-position: -200% 0; }
  100% { background-position: 200% 0; }
}

@keyframes meterAnim {
  from { width: 0%; }
}

/* Centered Header / Logo */
.header-centered {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  margin-bottom: 1.8rem;
  gap: 0.75rem;
}

.brand-logo-center {
  font-family: 'Inter', sans-serif;
  font-size: 2.7rem;
  font-weight: 850;
  letter-spacing: -0.04em;
  color: #FFFFFF;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.65rem;
  line-height: 1.1;
  background: linear-gradient(135deg, #FFFFFF 30%, #C7D2FE 80%, #818CF8 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  animation: logoShine 4s ease-in-out infinite;
}

.brand-logo-icon {
  font-size: 2.2rem;
  line-height: 1;
  color: #818CF8;
  -webkit-text-fill-color: #818CF8;
}

.status-pill {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.76rem;
  font-weight: 600;
  padding: 0.35rem 0.85rem;
  border-radius: 999px;
  backdrop-filter: blur(8px);
  transition: all 0.25s ease;
}
.status-pill.online {
  background: rgba(16, 185, 129, 0.12);
  border: 1px solid rgba(16, 185, 129, 0.3);
  color: #6EE7B7;
}
.status-pill.offline {
  background: rgba(239, 68, 68, 0.12);
  border: 1px solid rgba(239, 68, 68, 0.3);
  color: #FCA5A5;
}
.pulse-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  display: inline-block;
}
.pulse-dot.green {
  background: #10B981;
  animation: haloPulse 2.2s infinite;
}
.pulse-dot.red {
  background: #EF4444;
  box-shadow: 0 0 8px #EF4444;
}

/* Dynamic Pipeline Banner */
.pipeline-banner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: linear-gradient(135deg, rgba(17, 23, 38, 0.85) 0%, rgba(13, 19, 32, 0.95) 100%);
  border: 1px solid var(--border-subtle);
  border-radius: 14px;
  padding: 1rem 1.4rem;
  margin-bottom: 1.8rem;
  backdrop-filter: blur(12px);
  position: relative;
  overflow: hidden;
  box-shadow: 0 6px 24px rgba(0, 0, 0, 0.25);
}
.pipeline-banner::before {
  content: "";
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 1px;
  background: linear-gradient(90deg, transparent, rgba(99, 102, 241, 0.6), transparent);
  background-size: 200% 100%;
  animation: beamFlow 3s linear infinite;
}

.pipe-step {
  display: flex;
  flex-direction: column;
  gap: 0.15rem;
}
.pipe-title {
  font-size: 0.86rem;
  font-weight: 650;
  color: var(--text-main);
  letter-spacing: -0.01em;
}
.pipe-sub {
  font-size: 0.73rem;
  color: var(--text-dim);
}
.pipe-step.center .pipe-title {
  color: #A5B4FC;
}
.pipe-flow-arrow {
  display: flex;
  align-items: center;
  gap: 4px;
  color: var(--text-dim);
  font-size: 0.85rem;
}
.flow-line {
  width: 28px;
  height: 2px;
  background: linear-gradient(90deg, rgba(255, 255, 255, 0.1), #818CF8);
  border-radius: 2px;
}

/* KPI Summary Cards */
.kpi-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 0.85rem;
  margin-bottom: 1.6rem;
}
.kpi-card {
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: 12px;
  padding: 1rem 1.1rem;
  position: relative;
  overflow: hidden;
  transition: transform 0.25s ease, box-shadow 0.25s ease, border-color 0.25s ease;
}
.kpi-card:hover {
  transform: translateY(-3px);
  border-color: rgba(255, 255, 255, 0.2);
  box-shadow: 0 10px 25px rgba(0, 0, 0, 0.35);
}
.kpi-card::after {
  content: "";
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 2.5px;
}
.kpi-card.total::after { background: #818CF8; }
.kpi-card.danger::after { background: var(--danger-color); }
.kpi-card.warn::after { background: var(--warn-color); }
.kpi-card.ok::after { background: var(--ok-color); }

.kpi-num {
  font-size: 1.95rem;
  font-weight: 800;
  line-height: 1.1;
  letter-spacing: -0.02em;
}
.kpi-label {
  font-size: 0.73rem;
  font-weight: 650;
  letter-spacing: 0.07em;
  text-transform: uppercase;
  color: var(--text-dim);
  margin-top: 0.4rem;
}
.kpi-sub {
  font-size: 0.72rem;
  color: var(--text-muted);
  margin-top: 0.25rem;
}

/* Tool Cards with Dynamic Elevation & Glow */
.tool-card {
  background: var(--bg-card);
  border: 1px solid var(--border-card);
  border-radius: 14px;
  padding: 1.25rem 1.45rem;
  margin-bottom: 1rem;
  position: relative;
  transition: transform 0.22s cubic-bezier(0.16, 1, 0.3, 1), box-shadow 0.22s ease, border-color 0.22s ease;
}
.tool-card:hover {
  transform: translateY(-3px);
  border-color: rgba(255, 255, 255, 0.22);
}
.tool-card.d {
  border-left: 4px solid var(--danger-color);
}
.tool-card.d:hover {
  box-shadow: 0 12px 30px rgba(0, 0, 0, 0.4), 0 0 20px rgba(239, 68, 68, 0.12);
}
.tool-card.s {
  border-left: 4px solid var(--warn-color);
}
.tool-card.s:hover {
  box-shadow: 0 12px 30px rgba(0, 0, 0, 0.4), 0 0 20px rgba(245, 158, 11, 0.12);
}
.tool-card.h {
  border-left: 4px solid var(--ok-color);
}
.tool-card.h:hover {
  box-shadow: 0 12px 30px rgba(0, 0, 0, 0.4), 0 0 20px rgba(16, 185, 129, 0.12);
}

.card-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  margin-bottom: 0.8rem;
  flex-wrap: wrap;
}
.tool-identity {
  display: flex;
  align-items: center;
  gap: 0.65rem;
  flex-wrap: wrap;
}
.tool-name {
  font-family: 'JetBrains Mono', monospace;
  font-size: 1.08rem;
  font-weight: 700;
  color: #FFFFFF;
  letter-spacing: -0.01em;
}
.server-badge {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.74rem;
  color: var(--text-muted);
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(255, 255, 255, 0.08);
  padding: 0.15rem 0.5rem;
  border-radius: 6px;
}

.verdict-tag {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.73rem;
  font-weight: 750;
  letter-spacing: 0.07em;
  text-transform: uppercase;
  padding: 0.32rem 0.75rem;
  border-radius: 999px;
  white-space: nowrap;
}
.verdict-tag.d {
  background: var(--danger-glow);
  color: var(--danger-tag);
  border: 1px solid var(--danger-border);
}
.verdict-tag.s {
  background: var(--warn-glow);
  color: var(--warn-tag);
  border: 1px solid var(--warn-border);
}
.verdict-tag.h {
  background: var(--ok-glow);
  color: var(--ok-tag);
  border: 1px solid var(--ok-border);
}

.status-dot {
  width: 6.5px;
  height: 6.5px;
  border-radius: 50%;
  display: inline-block;
}
.verdict-tag.d .status-dot { background: var(--danger-color); box-shadow: 0 0 8px var(--danger-color); }
.verdict-tag.s .status-dot { background: var(--warn-color); box-shadow: 0 0 8px var(--warn-color); }
.verdict-tag.h .status-dot { background: var(--ok-color); box-shadow: 0 0 8px var(--ok-color); }

/* Description Box - Enlarged, legible, prominent */
.desc-box {
  background: var(--bg-inner);
  border: 1px solid rgba(255, 255, 255, 0.09);
  border-radius: 10px;
  padding: 1.05rem 1.25rem;
  margin-top: 0.75rem;
  box-shadow: inset 0 2px 8px rgba(0, 0, 0, 0.3);
}
.desc-header-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 0.55rem;
  border-bottom: 1px solid rgba(255, 255, 255, 0.05);
  padding-bottom: 0.35rem;
}
.desc-label {
  font-size: 0.75rem;
  font-weight: 650;
  letter-spacing: 0.09em;
  text-transform: uppercase;
  color: #A5B4FC;
}
.desc-indicator {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.72rem;
  color: var(--text-dim);
}
.desc-code {
  font-family: 'JetBrains Mono', monospace;
  font-size: 1.02rem;
  color: #E2E8F0;
  line-height: 1.68;
  white-space: pre-wrap;
  word-break: break-word;
}

/* Card Analysis & Dynamic Risk Gauge */
.card-analysis {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1.2rem;
  margin-top: 0.95rem;
  padding-top: 0.85rem;
  border-top: 1px solid var(--border-subtle);
  font-size: 0.85rem;
  color: var(--text-muted);
  flex-wrap: wrap;
}
.analysis-col {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}
.score-pill {
  font-weight: 700;
  color: var(--text-main);
  font-size: 0.9rem;
}
.meter-track {
  width: 110px;
  height: 7px;
  background: rgba(255, 255, 255, 0.08);
  border-radius: 999px;
  overflow: hidden;
  display: inline-block;
  vertical-align: middle;
}
.meter-fill {
  height: 100%;
  border-radius: 999px;
  animation: meterAnim 0.6s cubic-bezier(0.16, 1, 0.3, 1) forwards;
}
.meter-fill.d {
  background: linear-gradient(90deg, #F87171, var(--danger-color));
  box-shadow: 0 0 10px rgba(239, 68, 68, 0.5);
}
.meter-fill.s {
  background: linear-gradient(90deg, #FBBF24, var(--warn-color));
  box-shadow: 0 0 10px rgba(245, 158, 11, 0.5);
}
.meter-fill.h {
  background: linear-gradient(90deg, #34D399, var(--ok-color));
  box-shadow: 0 0 10px rgba(16, 185, 129, 0.5);
}

.alert-tag {
  display: inline-block;
  font-size: 0.74rem;
  font-weight: 600;
  background: var(--danger-glow);
  color: var(--danger-tag);
  border: 1px solid var(--danger-border);
  padding: 0.12rem 0.5rem;
  border-radius: 5px;
  margin-right: 0.35rem;
}
.no-alerts {
  font-size: 0.82rem;
  color: var(--text-dim);
}

.reason-container {
  margin-top: 0.8rem;
  font-size: 0.88rem;
  color: #E2E8F0;
  background: rgba(255, 255, 255, 0.02);
  border-left: 2px solid var(--border-subtle);
  padding: 0.65rem 0.95rem;
  border-radius: 0 8px 8px 0;
  line-height: 1.55;
}
.reason-container b {
  color: var(--text-muted);
  font-weight: 500;
}

/* Fallback Notice */
.notice-box {
  background: rgba(245, 158, 11, 0.08);
  border: 1px solid rgba(245, 158, 11, 0.25);
  border-radius: 12px;
  padding: 0.9rem 1.2rem;
  font-size: 0.86rem;
  color: #FDE68A;
  margin-bottom: 1.4rem;
  line-height: 1.5;
}

/* Streamlit Widget Tuning */
div[data-testid="stRadio"] > label { display: none; }
div[data-testid="stRadio"] div[role="radiogroup"] {
  gap: 0.45rem;
  flex-wrap: wrap;
}
div[data-testid="stRadio"] div[role="radiogroup"] label {
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: 8px;
  padding: 0.35rem 0.9rem;
  color: var(--text-muted);
  font-size: 0.84rem;
  cursor: pointer;
  transition: all 0.2s ease;
}
div[data-testid="stRadio"] div[role="radiogroup"] label:hover {
  border-color: rgba(255, 255, 255, 0.25);
  color: var(--text-main);
}
div[data-testid="stTextInput"] input {
  background: var(--bg-card) !important;
  border: 1px solid var(--border-subtle) !important;
  color: var(--text-main) !important;
  border-radius: 8px !important;
  font-size: 0.88rem !important;
}
div[data-testid="stButton"] button {
  background: #4F46E5 !important;
  color: #FFFFFF !important;
  border: none !important;
  border-radius: 8px !important;
  font-weight: 600 !important;
  padding: 0.55rem 1.25rem !important;
  box-shadow: 0 2px 12px rgba(79, 70, 229, 0.3) !important;
  transition: all 0.2s ease !important;
}
div[data-testid="stButton"] button:hover {
  background: #4338CA !important;
  box-shadow: 0 4px 18px rgba(79, 70, 229, 0.5) !important;
  transform: translateY(-1px);
}
</style>
"""


def esc(s) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def scan_all(catalogue):
    """Run the scanner over every tool; return a list of result dicts."""
    results = []
    for tool in catalogue:
        r = scan_outil(tool["name"], tool["description"])
        r["server"] = tool.get("server", "")
        r["description"] = tool["description"]
        results.append(r)
    return results


def _judge_available() -> bool:
    """Probe the judge once on a trivial description to verify availability."""
    try:
        from judge import judge_tool
        judge_tool("probe", "Adds two numbers and returns the sum.")
        return True
    except Exception:
        return False


def render_summary_grid(st, results):
    n_total = len(results)
    n_d = sum(1 for r in results if r["verdict"] == DANGEROUS)
    n_s = sum(1 for r in results if r["verdict"] == SUSPICIOUS)
    n_h = sum(1 for r in results if r["verdict"] == HEALTHY)

    pct_d = f"{(n_d / n_total * 100):.0f}% du total" if n_total else "0%"
    pct_h = f"{(n_h / n_total * 100):.0f}% du total" if n_total else "0%"

    st.markdown(
        f"""
        <div class="kpi-grid">
          <div class="kpi-card total">
            <div class="kpi-num" style="color:#A5B4FC">{n_total}</div>
            <div class="kpi-label">Outils analysés</div>
            <div class="kpi-sub">Catalogue inspecté</div>
          </div>
          <div class="kpi-card danger">
            <div class="kpi-num" style="color:var(--danger-color)">{n_d}</div>
            <div class="kpi-label">Retirés (Bloqués)</div>
            <div class="kpi-sub">{pct_d} neutralisés</div>
          </div>
          <div class="kpi-card warn">
            <div class="kpi-num" style="color:var(--warn-color)">{n_s}</div>
            <div class="kpi-label">À revoir (Suspects)</div>
            <div class="kpi-sub">Signalés pour audit</div>
          </div>
          <div class="kpi-card ok">
            <div class="kpi-num" style="color:var(--ok-color)">{n_h}</div>
            <div class="kpi-label">Transmis (Sains)</div>
            <div class="kpi-sub">{pct_h} autorisés</div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_tool_card(st, r, show_desc=True):
    label, cls = LABEL.get(r["verdict"], (r["verdict"], "s"))
    score_val = r.get("score")
    score_display = "—" if score_val is None else f"{score_val}/10"

    # Gauge fill width
    fill_pct = 0 if score_val is None else min(100, max(6, score_val * 10))

    alertes = r.get("alertes") or []
    if alertes:
        alerts_html = "".join(f'<span class="alert-tag">{esc(a)}</span>' for a in alertes)
    else:
        alerts_html = '<span class="no-alerts">aucune alerte statique</span>'

    reason = esc(r.get("raison", "")) or "—"
    desc = r.get("description", "")
    if not show_desc and len(desc) > 95:
        desc = desc[:95] + "…"

    st.markdown(
        f"""
        <div class="tool-card {cls}">
          <div class="card-top">
            <div class="tool-identity">
              <span class="tool-name">{esc(r['name'])}</span>
              <span class="server-badge">serveur: {esc(r.get('server',''))}</span>
            </div>
            <div class="verdict-tag {cls}">
              <span class="status-dot"></span>
              {label}
            </div>
          </div>

          <div class="desc-box">
            <div class="desc-header-row">
              <span class="desc-label">Description déclarée dans MCP</span>
              <span class="desc-indicator">read-only payload</span>
            </div>
            <div class="desc-code">{esc(desc)}</div>
          </div>

          <div class="card-analysis">
            <div class="analysis-col">
              <span>Score Juge LLM&nbsp;:</span>
              <span class="score-pill">{score_display}</span>
              <div class="meter-track">
                <div class="meter-fill {cls}" style="width: {fill_pct}%;"></div>
              </div>
            </div>
            <div class="analysis-col">
              <span>Règles&nbsp;:</span>
              <div>{alerts_html}</div>
            </div>
          </div>

          <div class="reason-container">
            <b>Décision&nbsp;:</b> {reason}
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def run_cli() -> int:
    """Terminal fallback demo — works even without Streamlit."""
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    catalogue = load_catalogue(include_clean=True)
    print("\n" + "=" * 60)
    print("MCP_SCANNER — Rapport de filtrage Tool Poisoning")
    print("=" * 60)
    results = scan_all(catalogue)
    order = {DANGEROUS: 0, SUSPICIOUS: 1, HEALTHY: 2}
    for r in sorted(results, key=lambda x: order.get(x["verdict"], 1)):
        label = LABEL.get(r["verdict"], (r["verdict"], ""))[0]
        score = "—" if r.get("score") is None else f"{r['score']}/10"
        alertes = ", ".join(r.get("alertes") or []) or "—"
        print(f"[{label:20}] {r['name']:24} score={score:6} règles={alertes}")
        print(f"  Raison : {r.get('raison', '')}\n")
    n_d = sum(1 for r in results if r["verdict"] == DANGEROUS)
    n_s = sum(1 for r in results if r["verdict"] == SUSPICIOUS)
    n_h = sum(1 for r in results if r["verdict"] == HEALTHY)
    print("-" * 60)
    print(f"Total : {len(results)} outils | {n_d} retirés | {n_s} suspects | {n_h} transmis\n")
    return 0


def main():
    import streamlit as st

    st.set_page_config(page_title="MCP_SCANNER", page_icon="⬡", layout="centered")
    st.markdown(CSS, unsafe_allow_html=True)

    judge_ok = _judge_available()
    status_pill_html = (
        '<div class="status-pill online"><span class="pulse-dot green"></span> Juge LLM : Actif (Claude Bedrock)</div>'
        if judge_ok
        else '<div class="status-pill offline"><span class="pulse-dot red"></span> Juge LLM : Mode Dégradé (Fail-closed)</div>'
    )

    # Centered Header with logo only, texts removed as requested
    st.markdown(
        f"""
        <div class="header-centered">
          <div class="brand-logo-center">
            <span class="brand-logo-icon">⬡</span> MCP_SCANNER
          </div>
          <div>
            {status_pill_html}
          </div>
        </div>

        <div class="pipeline-banner">
          <div class="pipe-step">
            <span class="pipe-title">Serveurs MCP</span>
            <span class="pipe-sub">8 outils annoncés</span>
          </div>
          <div class="pipe-flow-arrow">
            <div class="flow-line"></div>
            <span>►</span>
          </div>
          <div class="pipe-step center">
            <span class="pipe-title">MCP_SCANNER</span>
            <span class="pipe-sub">Règles + Juge sémantique LLM</span>
          </div>
          <div class="pipe-flow-arrow">
            <div class="flow-line"></div>
            <span>►</span>
          </div>
          <div class="pipe-step">
            <span class="pipe-title">Agent IA Protégé</span>
            <span class="pipe-sub">Outils sains uniquement</span>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not judge_ok:
        st.markdown(
            '<div class="notice-box"><b>Attention :</b> Juge LLM indisponible '
            '(credentials AWS / modèle Bedrock manquants ou hors-ligne). '
            'Le scanner applique la politique <b>fail-closed</b>&nbsp;: tout outil non vérifié est classé '
            '« dangereux » par sécurité. Avec le juge configuré, les outils sains sont validés.</div>',
            unsafe_allow_html=True,
        )

    catalogue = load_catalogue(include_clean=True)

    # Initialize results in session state
    if "results" not in st.session_state:
        st.session_state["results"] = None

    c1, c2 = st.columns([1, 1])
    with c1:
        run_label = "Réanalyser les outils" if st.session_state["results"] else "Analyser les outils"
        run_clicked = st.button(run_label, type="primary", use_container_width=True)
    with c2:
        show_desc = st.toggle("Afficher les descriptions complètes", value=True)

    if run_clicked or (st.session_state["results"] is None and run_clicked):
        progress_bar = st.progress(0.0, text="Inspection des outils via le scanner...")
        results = []
        for i, tool in enumerate(catalogue, start=1):
            r = scan_outil(tool["name"], tool["description"])
            r["server"] = tool.get("server", "")
            r["description"] = tool["description"]
            results.append(r)
            progress_bar.progress(i / len(catalogue), text=f"Analyse {i}/{len(catalogue)} : {tool['name']}")
            time.sleep(0.04)
        progress_bar.empty()
        st.session_state["results"] = results

    results = st.session_state.get("results")

    if not results:
        st.markdown(
            f'<div style="color:var(--text-dim); font-size:0.88rem; margin-top:1rem; padding:1.4rem; border:1px dashed var(--border-subtle); border-radius:12px; text-align:center;">'
            f'{len(catalogue)} outils prêts pour inspection ({sum(1 for t in catalogue if t["attack_class"])} piégés, '
            f'{sum(1 for t in catalogue if not t["attack_class"])} sains). '
            f'Cliquez sur « Analyser les outils » pour démarrer le filtrage.</div>',
            unsafe_allow_html=True,
        )
        return

    # Render summary metrics grid
    render_summary_grid(st, results)

    # Filters and search
    f_col1, f_col2 = st.columns([2, 1])
    with f_col1:
        filter_opt = st.radio(
            "Filtrer par statut",
            options=["Tous", "Retirés (Dangereux)", "Transmis (Sains)", "À revoir (Suspects)"],
            horizontal=True,
        )
    with f_col2:
        search_query = st.text_input("Recherche", placeholder="Filtrer par nom / serveur...", label_visibility="collapsed")

    # Filter results
    filtered = results
    if filter_opt == "Retirés (Dangereux)":
        filtered = [r for r in filtered if r["verdict"] == DANGEROUS]
    elif filter_opt == "Transmis (Sains)":
        filtered = [r for r in filtered if r["verdict"] == HEALTHY]
    elif filter_opt == "À revoir (Suspects)":
        filtered = [r for r in filtered if r["verdict"] == SUSPICIOUS]

    if search_query:
        sq = search_query.strip().lower()
        filtered = [
            r for r in filtered
            if sq in r["name"].lower() or sq in r.get("server", "").lower() or sq in r.get("raison", "").lower()
        ]

    st.write("")

    order = {DANGEROUS: 0, SUSPICIOUS: 1, HEALTHY: 2}
    sorted_tools = sorted(filtered, key=lambda x: order.get(x["verdict"], 1))

    if not sorted_tools:
        st.markdown('<div style="color:var(--text-dim); font-size:0.86rem; padding:1.2rem; text-align:center;">Aucun outil ne correspond aux filtres actuels.</div>', unsafe_allow_html=True)
    else:
        for r in sorted_tools:
            render_tool_card(st, r, show_desc=show_desc)


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
