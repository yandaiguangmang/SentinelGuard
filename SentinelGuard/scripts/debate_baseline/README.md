# PhishDebate — Reproduction

Unofficial reproduction of **"PhishDebate: An LLM-Based Multi-Agent Framework for Phishing Website Detection"**
(IEEE BigData 2025 · arXiv:2506.15656 · Wenhao Li, Selvakumar Manickam, Yung-Wey Chong, Shankar Karuppayah)

> No official code was released by the authors. This reproduction is based solely on the paper.

---

## Architecture Overview

```
                         ┌────────────────────────────────────────────────────┐
                         │                  PhishDebate Framework              │
                         │                                                      │
 Website Input ──────────►  Round 1: Independent Analysis (4 Specialist Agents) │
 (URL, HTML, Text)       │    ┌──────────────┐  ┌──────────────┐               │
                         │    │ URL Analyst  │  │ HTML Struct  │               │
                         │    └──────┬───────┘  └──────┬───────┘               │
                         │    ┌──────────────┐  ┌──────────────┐               │
                         │    │ Content Sem. │  │ Brand Imper. │               │
                         │    └──────┬───────┘  └──────┬───────┘               │
                         │           └──────────────────┘                       │
                         │                    │                                  │
                         │             ┌──────▼──────┐                          │
                         │             │  Moderator  │ ◄── Consensus check       │
                         │             └──────┬──────┘                          │
                         │          consensus?│                                  │
                         │        NO  ◄───────┤───────► YES                     │
                         │        │           │              │                   │
                         │  Round 2+ Debate   │         skip to Judge            │
                         │  (agents see each  │                                  │
                         │   other's views)   │                                  │
                         │        │           │                                  │
                         │        └───────────┤                                  │
                         │                    ▼                                  │
                         │             ┌──────────────┐                          │
                         │             │    Judge     │ ◄── Always decides        │
                         │             └──────┬───────┘                          │
                         └────────────────────┼───────────────────────────────┘
                                              │
                                    PHISHING / LEGITIMATE
```

---

## Installation

```bash
pip install -r requirements.txt
```

Required environment variables:

| Provider | Variable | Models |
|---|---|---|
| OpenAI | `OPENAI_API_KEY` | `gpt-4o`, `gpt-4o-mini` |
| Google | `GOOGLE_API_KEY` | `gemini-2.0-flash` |
| Custom endpoint | `OPENAI_COMPATIBLE_BASE_URL` + `OPENAI_COMPATIBLE_API_KEY` | Ollama, Together AI, etc. |

---

## Datasets

The paper uses two datasets. Download and place them as shown:

### 1. Mendeley Phishing Website Dataset
- **Source**: https://data.mendeley.com/datasets/72ptz43s9v/1
- Place as:
  ```
  data/mendeley/
    phishing/
      001.url   001.html
      002.url   002.html  ...
    legitimate/
      001.url   001.html  ...
  ```
  Or as a CSV with columns `url`, `html`, `label`.

### 2. TR-OP Dataset
- **Source**: https://github.com/koide-t/ChatPhishDetector (referenced in paper)
- Same structure as Mendeley.

---

## Quick Demo (single URL)

```bash
export OPENAI_API_KEY=sk-...

# Analyze a URL with optional HTML file
python demo.py --url "https://suspicious-domain.xyz/secure-login" \
               --html_file page.html \
               --model gpt-4o-mini \
               --max_rounds 2
```

---

## Full Experiment Reproduction

### Basic evaluation (PhishDebate only)

```bash
python run_experiment.py \
  --data_dir ./data/mendeley \
  --model gpt-4o-mini \
  --max_samples 1000 \
  --max_rounds 2 \
  --output_dir results/
```

### Comparative evaluation (Table II in paper)

```bash
python run_experiment.py \
  --data_dir ./data/mendeley \
  --model gpt-4o-mini \
  --max_samples 1000 \
  --compare_baselines \
  --output_dir results/
```

### Scenario analysis — agent exclusion (Table III in paper)

```bash
python run_experiment.py \
  --data_dir ./data/mendeley \
  --model gpt-4o-mini \
  --max_samples 1000 \
  --scenario_analysis \
  --output_dir results/
```

### Cache preprocessed data (avoids re-parsing HTML on reruns)

```bash
python run_experiment.py \
  --data_dir ./data/mendeley \
  --model gpt-4o-mini \
  --cache_preprocessed ./data/mendeley_preprocessed.json \
  --max_samples 1000
```

---

## Python API

```python
from phishdebate import PhishDebate, LLMClient

client = LLMClient(model="gpt-4o-mini")
framework = PhishDebate(
    client=client,
    max_rounds=2,
    consensus_threshold=0.75,
    # active_agents=["URL Analyst", "HTML Structure"]  # optional: exclude agents
)

result = framework.detect(
    url="https://example.com/login",
    html="<html>...</html>",
    text="Enter your password below",
)

print(result.assessment)    # "PHISHING" or "LEGITIMATE"
print(result.confidence)    # float 0–1
print(result.total_rounds)  # 1 or 2 (or more)
```

---

## Project Structure

```
phishdebate/
├── __init__.py
├── framework.py          # PhishDebate orchestrator (Algorithm 1)
├── run_experiment.py     # Full experiment runner
├── demo.py               # Single-URL quick demo
├── agents/
│   ├── prompts.py        # All prompt templates (from paper)
│   ├── agents.py         # 6 agent implementations
│   └── llm_client.py     # LLM backend (OpenAI / Gemini / compatible)
├── baselines/
│   └── baselines.py      # Single Agent + CoT baselines
├── data/
│   └── preprocessing.py  # Algorithm 2: data pipeline
├── evaluation/
│   └── metrics.py        # TPR, TNR, FPR, FNR, Precision, Accuracy, F1
└── requirements.txt
```

---

## Expected Results (from paper, GPT-4o-mini, Mendeley dataset, n=1000)

| Method | Precision | Accuracy | Recall | F1 |
|---|---|---|---|---|
| Single Agent | 0.6057 | 0.6700 | 0.9740 | 0.7469 |
| CoT | 0.8861 | 0.9070 | 0.9340 | 0.9094 |
| **PhishDebate** | **0.9057** | **0.9390** | **0.9800** | **0.9414** |

---

## Notes & Limitations

- The paper's supplementary prompt templates for HTML Structure, Content Semantic, Brand Impersonation, Moderator, and Judge agents were **not published**. The prompts in this reproduction are reconstructed from the paper's descriptions.
- The paper used `Rmax = 2` as the default (based on the case study).
- Qwen2.5-vl-72b-instruct requires an OpenAI-compatible endpoint (Together AI, Hyperbolic, etc.).
- API costs: each sample requires ~6 LLM calls per round × N rounds. Budget accordingly.
