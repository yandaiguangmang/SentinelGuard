#!/usr/bin/env python3
"""
Quick single-URL demo for PhishDebate.
Usage:
  python demo.py --url "https://example.com" --html_file page.html
  python demo.py --url "https://suspicious-site.xyz/login" --text "Verify your account now!"

Set OPENAI_API_KEY before running.
"""

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from phishdebate import PhishDebate, LLMClient
from phishdebate.data.preprocessing import preprocess_sample


def main():
    p = argparse.ArgumentParser(description="PhishDebate single-URL demo")
    p.add_argument("--url", required=True, help="URL to analyze")
    p.add_argument("--html_file", default=None, help="Path to saved HTML file")
    p.add_argument("--text", default="", help="Visible text (optional if HTML provided)")
    p.add_argument("--model", default="gpt-4o-mini", help="LLM model")
    p.add_argument("--max_rounds", type=int, default=2, help="Max debate rounds")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()

    if args.verbose:
        import logging
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s: %(message)s")

    # Load HTML
    raw_html = ""
    if args.html_file:
        raw_html = Path(args.html_file).read_text(encoding="utf-8", errors="replace")

    sample = preprocess_sample(url=args.url, raw_html=raw_html, label=-1)
    if sample is None:
        # Use raw inputs
        html = raw_html
        text = args.text
    else:
        html = sample.html
        text = sample.text or args.text

    # Run framework
    client = LLMClient(model=args.model)
    framework = PhishDebate(client=client, max_rounds=args.max_rounds)

    print(f"\n🔍 Analyzing URL: {args.url}")
    print(f"   Model: {args.model} | Max rounds: {args.max_rounds}\n")

    result = framework.detect(url=args.url, html=html, text=text)

    emoji = "🚨" if result.assessment == "PHISHING" else "✅"
    print(f"{emoji}  Verdict: {result.assessment}")
    print(f"   Confidence: {result.confidence:.2f}")
    print(f"   Rounds: {result.total_rounds} | Consensus: {result.consensus_reached}")
    print(f"   Time: {result.elapsed_seconds:.1f}s")
    print(f"\n📝 Judge Reasoning:")
    if result.judge_response:
        print(f"   {result.judge_response.reasoning[:500]}")
        if result.judge_response.key_evidence:
            print(f"\n🔑 Key Evidence:")
            for ev in result.judge_response.key_evidence[:5]:
                print(f"   • {ev}")

    print(f"\n📊 Agent Summary (final round):")
    last_round = max(r.round_num for r in result.all_agent_responses)
    for resp in result.all_agent_responses:
        if resp.round_num == last_round:
            print(f"   [{resp.agent_name}] {resp.claim} ({resp.confidence:.2f})")


if __name__ == "__main__":
    main()
