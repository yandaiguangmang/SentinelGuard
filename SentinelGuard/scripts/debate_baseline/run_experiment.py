#!/usr/bin/env python3
"""
PhishDebate Reproduction Script
================================
Reproduces the experiments from:
  "PhishDebate: An LLM-Based Multi-Agent Framework for Phishing Website Detection"
  IEEE BigData 2025 — Wenhao Li, Selvakumar Manickam, Yung-Wey Chong, Shankar Karuppayah
  arXiv: 2506.15656

Usage examples
--------------
# Run full evaluation on Mendeley dataset:
  python run_experiment.py --data_dir ./data/mendeley --model gpt-4o-mini

# Run comparative evaluation (PhishDebate vs Single Agent vs CoT):
  python run_experiment.py --data_dir ./data/mendeley --model gpt-4o-mini --compare_baselines

# Quick test on 10 samples:
  python run_experiment.py --data_dir ./data/mendeley --model gpt-4o-mini --max_samples 10

# Scenario analysis (exclude agents one by one):
  python run_experiment.py --data_dir ./data/mendeley --model gpt-4o-mini --scenario_analysis

# Use a custom CSV file:
  python run_experiment.py --data_dir ./data/my_dataset.csv --model gpt-4o-mini

Environment variables required
--------------------------------
  OPENAI_API_KEY        — for gpt-4o, gpt-4o-mini
  GOOGLE_API_KEY        — for gemini-2.0-flash
  OPENAI_COMPATIBLE_BASE_URL / OPENAI_COMPATIBLE_API_KEY — for local/other endpoints
"""

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

# ── Path setup ───────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))

from phishdebate.agents.llm_client import LLMClient
from phishdebate.framework import PhishDebate, PhishDebateResult
from phishdebate.baselines.baselines import SingleAgentBaseline, CoTBaseline
from phishdebate.data.preprocessing import (
    load_mendeley_dataset, load_samples_from_json, save_samples_to_json, WebsiteSample
)
from phishdebate.evaluation.metrics import EvalMetrics, ResultsLogger, RunRecord, compare_methods

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("phishdebate.run")


# ─────────────────────────────────────────────────────────────────────────────
# Argument parsing
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description="PhishDebate Experiment Runner")
    p.add_argument("--data_dir", required=True,
                   help="Path to dataset directory or CSV file.")
    p.add_argument("--model", default="gpt-4o-mini",
                   choices=["gpt-4o", "gpt-4o-mini", "gemini-2.0-flash",
                            "qwen2.5-vl-72b-instruct", "custom"],
                   help="LLM model to use.")
    p.add_argument("--max_samples", type=int, default=None,
                   help="Limit total samples (phishing+legitimate). Default: all.")
    p.add_argument("--max_rounds", type=int, default=2,
                   help="Maximum debate rounds (paper: 1–3). Default: 2.")
    p.add_argument("--consensus_threshold", type=float, default=0.75,
                   help="Moderator confidence threshold for early termination.")
    p.add_argument("--output_dir", default="results",
                   help="Directory for saving results.")
    p.add_argument("--cache_preprocessed", default=None,
                   help="Path to cache/load preprocessed samples JSON.")
    p.add_argument("--compare_baselines", action="store_true",
                   help="Also run Single Agent and CoT baselines for comparison.")
    p.add_argument("--scenario_analysis", action="store_true",
                   help="Run scenario analysis (exclude each agent one at a time).")
    p.add_argument("--verbose", action="store_true",
                   help="Enable debug logging.")
    return p.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# Experiment runners
# ─────────────────────────────────────────────────────────────────────────────

def run_phishdebate(
    samples: list[WebsiteSample],
    client: LLMClient,
    max_rounds: int,
    consensus_threshold: float,
    output_dir: str,
    run_name: str = "phishdebate",
    active_agents: list[str] | None = None,
) -> EvalMetrics:
    framework = PhishDebate(
        client=client,
        max_rounds=max_rounds,
        consensus_threshold=consensus_threshold,
        active_agents=active_agents,
    )
    rl = ResultsLogger(output_dir=output_dir, run_name=run_name)
    total = len(samples)

    for i, sample in enumerate(samples, 1):
        logger.info(f"[{i}/{total}] {run_name} | {sample.url[:70]}")
        try:
            result: PhishDebateResult = framework.detect(
                url=sample.url,
                html=sample.html,
                text=sample.text,
            )
            record = RunRecord(
                sample_id=sample.sample_id,
                url=sample.url,
                true_label=sample.label,
                predicted=result.assessment,
                confidence=result.confidence,
                total_rounds=result.total_rounds,
                early_termination=result.early_termination,
                consensus_reached=result.consensus_reached,
                elapsed_seconds=result.elapsed_seconds,
                judge_reasoning=result.judge_response.reasoning if result.judge_response else "",
            )
            rl.log(record)
            correct = "✓" if (result.label == sample.label) else "✗"
            logger.info(
                f"  {correct} predicted={result.assessment} "
                f"(true={'PHISHING' if sample.label==1 else 'LEGITIMATE'}) "
                f"conf={result.confidence:.2f} rounds={result.total_rounds} "
                f"time={result.elapsed_seconds:.1f}s"
            )
        except Exception as e:
            logger.error(f"  Error on sample {sample.sample_id}: {e}")

    rl.save_json()
    rl.print_report()
    return rl.metrics


def run_baseline(
    samples: list[WebsiteSample],
    baseline,
    output_dir: str,
    run_name: str,
) -> EvalMetrics:
    rl = ResultsLogger(output_dir=output_dir, run_name=run_name)
    total = len(samples)

    for i, sample in enumerate(samples, 1):
        logger.info(f"[{i}/{total}] {run_name} | {sample.url[:70]}")
        try:
            result = baseline.detect(url=sample.url, html=sample.html, text=sample.text)
            record = RunRecord(
                sample_id=sample.sample_id,
                url=sample.url,
                true_label=sample.label,
                predicted=result.assessment,
                confidence=result.confidence,
                total_rounds=1,
                early_termination=False,
                consensus_reached=False,
                elapsed_seconds=result.elapsed_seconds,
                judge_reasoning=result.reasoning,
            )
            rl.log(record)
            correct = "✓" if (result.label == sample.label) else "✗"
            logger.info(
                f"  {correct} predicted={result.assessment} "
                f"conf={result.confidence:.2f} time={result.elapsed_seconds:.1f}s"
            )
        except Exception as e:
            logger.error(f"  Error on sample {sample.sample_id}: {e}")

    rl.save_json()
    rl.print_report()
    return rl.metrics


def run_scenario_analysis(
    samples: list[WebsiteSample],
    client: LLMClient,
    max_rounds: int,
    consensus_threshold: float,
    output_dir: str,
) -> dict[str, EvalMetrics]:
    ALL_AGENTS = ["URL Analyst", "HTML Structure", "Content Semantic", "Brand Impersonation"]
    scenarios = {
        "All Agents": ALL_AGENTS,
        "W/O URL Agent": [a for a in ALL_AGENTS if "URL" not in a],
        "W/O HTML Agent": [a for a in ALL_AGENTS if "HTML" not in a],
        "W/O Content Agent": [a for a in ALL_AGENTS if "Content" not in a],
        "W/O Brand Agent": [a for a in ALL_AGENTS if "Brand" not in a],
    }

    results = {}
    for scenario_name, agents in scenarios.items():
        safe_name = scenario_name.lower().replace(" ", "_").replace("/", "")
        logger.info(f"\n{'='*60}")
        logger.info(f"Scenario: {scenario_name} | agents={agents}")
        logger.info(f"{'='*60}")
        metrics = run_phishdebate(
            samples=samples,
            client=client,
            max_rounds=max_rounds,
            consensus_threshold=consensus_threshold,
            output_dir=output_dir,
            run_name=f"scenario_{safe_name}",
            active_agents=agents,
        )
        results[scenario_name] = metrics

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # ── Load data ─────────────────────────────────────────────────────────────
    if args.cache_preprocessed and Path(args.cache_preprocessed).exists():
        logger.info(f"Loading preprocessed samples from {args.cache_preprocessed}")
        samples = load_samples_from_json(args.cache_preprocessed)
        if args.max_samples:
            half = args.max_samples // 2
            phishing = [s for s in samples if s.label == 1][:half]
            legit = [s for s in samples if s.label == 0][:half]
            samples = phishing + legit
    else:
        logger.info(f"Loading dataset from {args.data_dir}")
        samples = load_mendeley_dataset(
            args.data_dir, max_samples=args.max_samples, balance=True
        )
        if args.cache_preprocessed:
            save_samples_to_json(samples, args.cache_preprocessed)
            logger.info(f"Cached preprocessed samples to {args.cache_preprocessed}")

    if not samples:
        logger.error("No samples loaded. Check your data directory.")
        sys.exit(1)

    n_phishing = sum(1 for s in samples if s.label == 1)
    n_legit = sum(1 for s in samples if s.label == 0)
    logger.info(f"Dataset: {len(samples)} samples ({n_phishing} phishing, {n_legit} legitimate)")

    # ── Build LLM client ──────────────────────────────────────────────────────
    provider = None
    if args.model == "custom":
        provider = "openai_compatible"
    client = LLMClient(model=args.model, provider=provider)

    output_dir = os.path.join(args.output_dir, args.model.replace("/", "_"))
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # ── Run PhishDebate ───────────────────────────────────────────────────────
    logger.info(f"\n{'='*60}")
    logger.info(f"Running PhishDebate | model={args.model} | max_rounds={args.max_rounds}")
    logger.info(f"{'='*60}")
    phishdebate_metrics = run_phishdebate(
        samples=samples,
        client=client,
        max_rounds=args.max_rounds,
        consensus_threshold=args.consensus_threshold,
        output_dir=output_dir,
        run_name="phishdebate",
    )

    all_metrics = {"PhishDebate (Ours)": phishdebate_metrics}

    # ── Baselines ─────────────────────────────────────────────────────────────
    if args.compare_baselines:
        logger.info(f"\n{'='*60}")
        logger.info("Running Single Agent baseline")
        logger.info(f"{'='*60}")
        single_metrics = run_baseline(
            samples=samples,
            baseline=SingleAgentBaseline(client),
            output_dir=output_dir,
            run_name="single_agent",
        )
        all_metrics["Single Agent"] = single_metrics

        logger.info(f"\n{'='*60}")
        logger.info("Running CoT baseline")
        logger.info(f"{'='*60}")
        cot_metrics = run_baseline(
            samples=samples,
            baseline=CoTBaseline(client),
            output_dir=output_dir,
            run_name="cot",
        )
        all_metrics["CoT"] = cot_metrics

        print("\n" + compare_methods(all_metrics))

    # ── Scenario analysis ─────────────────────────────────────────────────────
    if args.scenario_analysis:
        logger.info(f"\n{'='*60}")
        logger.info("Running Scenario Analysis (agent exclusion)")
        logger.info(f"{'='*60}")
        scenario_results = run_scenario_analysis(
            samples=samples,
            client=client,
            max_rounds=args.max_rounds,
            consensus_threshold=args.consensus_threshold,
            output_dir=output_dir,
        )
        print("\n=== Scenario Analysis Results ===")
        print(compare_methods(scenario_results))

    # ── Save summary ──────────────────────────────────────────────────────────
    summary_path = Path(output_dir) / "summary.json"
    summary = {
        "model": args.model,
        "max_rounds": args.max_rounds,
        "consensus_threshold": args.consensus_threshold,
        "n_samples": len(samples),
        "results": {k: v.to_dict() for k, v in all_metrics.items()},
    }
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    logger.info(f"\nSummary saved to {summary_path}")


if __name__ == "__main__":
    main()
