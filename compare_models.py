"""Run the 4 core tool-poisoning scenarios across several Bedrock models and
print a comparison table.

Reuses agent.py's SCENARIOS / run_scenario() directly instead of spawning one
subprocess per model -- just reassigns agent.MODEL_ID between runs (the
functions in agent.py look up the module-level global by name at call time,
so this works without touching agent.py itself).

Usage:
    python compare_models.py
    TRIALS=5 python compare_models.py
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import agent  # noqa: E402

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

MODELS = [
    ("Claude Haiku 4.5", "us.anthropic.claude-haiku-4-5-20251001-v1:0"),
    ("Claude Sonnet 4.5", "us.anthropic.claude-sonnet-4-5-20250929-v1:0"),
    ("Claude Opus 4.5", "us.anthropic.claude-opus-4-5-20251101-v1:0"),
    ("Claude Opus 4.8", "us.anthropic.claude-opus-4-8"),
    ("Claude Sonnet 5", "us.anthropic.claude-sonnet-5"),
    ("Claude Opus 5", "us.anthropic.claude-opus-5"),
    ("GPT-5.4", "us.openai.gpt-5.4"),
    ("GPT-5.5", "us.openai.gpt-5.5"),
    ("GPT-5.6 Sol", "us.openai.gpt-5.6-sol"),
]

# Only the 4 core attack scenarios (no high-stakes variants, no controls) --
# those are what we're comparing across models here.
CORE_NAMES = [
    "evil_pii (over-collection via a 'save preference' tool)",
    "evil_crosstool (cross-tool data leakage)",
    "evil_rugpull (delayed trigger, 3rd call)",
    "evil_shadow (shadowing the trusted send_email tool)",
]
SHORT_NAMES = ["pii", "crosstool", "rugpull", "shadow"]

scenarios = [s for s in agent.SCENARIOS if s.name in CORE_NAMES]
assert len(scenarios) == 4, f"expected 4 core scenarios, found {len(scenarios)}"

TRIALS = int(os.environ.get("TRIALS", "3"))


async def main() -> None:
    print(f"Essais par scénario : {TRIALS}")
    print(f"Modèles testés : {[label for label, _ in MODELS]}")

    # results[model_label][scenario.name] = list of outcome strings
    results: dict[str, dict[str, list]] = {label: {} for label, _ in MODELS}

    for label, model_id in MODELS:
        agent.MODEL_ID = model_id
        print(f"\n{'#' * 70}\n### MODELE : {label}  ({model_id})\n{'#' * 70}")
        for scenario in scenarios:
            outcomes = []
            for trial in range(1, TRIALS + 1):
                print(f"\n---- essai {trial}/{TRIALS} ----")
                try:
                    outcome = await agent.run_scenario(scenario)
                except Exception as exc:  # keep the sweep going even if one model/scenario misbehaves
                    print(f"[EXCEPTION non gérée] {exc!r}")
                    outcome = "error"
                outcomes.append(outcome)
            results[label][scenario.name] = outcomes
            n = len(outcomes)
            confirmed = outcomes.count("confirmed")
            print(f">>> RESUME {label} / {scenario.name} : {confirmed}/{n} confirmé(s) -- {outcomes}")

    # --- final comparison table -------------------------------------------------
    print(f"\n\n{'=' * 90}\n=== TABLEAU COMPARATIF (confirmé(s) / {TRIALS} essais) ===\n{'=' * 90}")
    col_w = 12
    header = "Modèle".ljust(22) + "".join(name.ljust(col_w) for name in SHORT_NAMES)
    print(header)
    print("-" * len(header))
    for label, _ in MODELS:
        row = [label.ljust(22)]
        for scenario in scenarios:
            outcomes = results[label].get(scenario.name, [])
            n = len(outcomes)
            confirmed = outcomes.count("confirmed")
            errors = outcomes.count("error")
            cell = f"{confirmed}/{n}" + (f" (err:{errors})" if errors else "")
            row.append(cell.ljust(col_w))
        print("".join(row))


if __name__ == "__main__":
    asyncio.run(main())
