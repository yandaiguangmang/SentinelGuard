"""
Data Preprocessing Pipeline (Algorithm 2 from the paper)
Supports: Mendeley Phishing Dataset, TR-OP Dataset, and custom CSV/directory formats.
"""

import csv
import json
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

logger = logging.getLogger(__name__)

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    logger.warning("BeautifulSoup not installed. HTML cleaning will be basic. "
                   "Run: pip install beautifulsoup4")


@dataclass
class WebsiteSample:
    url: str
    html: str          # Cleaned HTML (script/style/noscript removed)
    text: str          # Visible text extracted from HTML
    label: int         # 1 = phishing, 0 = legitimate
    sample_id: str = ""


def clean_html(raw_html: str) -> str:
    """
    Remove style, noscript, link[rel=stylesheet] tags from HTML.
    Matches Algorithm 2: CleanHTML step.
    """
    if not raw_html:
        return ""

    if BS4_AVAILABLE:
        soup = BeautifulSoup(raw_html, "html.parser")
        # Remove style, noscript, stylesheet links
        for tag in soup.find_all(["style", "noscript"]):
            tag.decompose()
        for tag in soup.find_all("link", rel="stylesheet"):
            tag.decompose()
        return str(soup)
    else:
        # Fallback: regex-based cleaning
        html = re.sub(r"<style[^>]*>.*?</style>", "", raw_html, flags=re.DOTALL | re.IGNORECASE)
        html = re.sub(r"<noscript[^>]*>.*?</noscript>", "", html, flags=re.DOTALL | re.IGNORECASE)
        return html


def extract_text(cleaned_html: str) -> str:
    """
    Extract visible text from cleaned HTML.
    Matches Algorithm 2: ExtractText step (also removes script tags).
    """
    if not cleaned_html:
        return ""

    if BS4_AVAILABLE:
        soup = BeautifulSoup(cleaned_html, "html.parser")
        for tag in soup.find_all("script"):
            tag.decompose()
        text = soup.get_text(separator=" ", strip=True)
        # Collapse whitespace
        text = re.sub(r"\s+", " ", text).strip()
        return text
    else:
        # Fallback
        html = re.sub(r"<script[^>]*>.*?</script>", "", cleaned_html, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r"<[^>]+>", " ", html)
        return re.sub(r"\s+", " ", text).strip()


def preprocess_sample(
    url: str, raw_html: str, label: int, sample_id: str = ""
) -> Optional[WebsiteSample]:
    """
    Full preprocessing pipeline for one sample (Algorithm 2).
    Returns None if URL or HTML is empty/invalid.
    """
    if not url or not raw_html:
        logger.debug(f"Skipping invalid sample {sample_id}: missing URL or HTML.")
        return None

    html = clean_html(raw_html)
    # Remove script tags from cleaned HTML for final version
    if BS4_AVAILABLE:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all("script"):
            tag.decompose()
        html = str(soup)
    else:
        html = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL | re.IGNORECASE)

    text = extract_text(html)

    return WebsiteSample(
        url=url,
        html=html,
        text=text,
        label=label,
        sample_id=sample_id,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Dataset Loaders
# ─────────────────────────────────────────────────────────────────────────────

def load_mendeley_dataset(
    data_dir: str,
    max_samples: Optional[int] = None,
    balance: bool = True,
) -> list[WebsiteSample]:
    """
    Load the Mendeley Phishing Website Dataset.

    Expected directory structure:
      data_dir/
        phishing/
          <id>.url   (one URL per file)
          <id>.html  (raw HTML)
        legitimate/
          <id>.url
          <id>.html

    Or a single CSV with columns: url, html, label (1=phishing, 0=legitimate).
    """
    data_dir = Path(data_dir)

    # Try CSV format first
    csv_candidates = list(data_dir.glob("*.csv"))
    if csv_candidates:
        return _load_csv(csv_candidates[0], max_samples=max_samples, balance=balance)

    # Try directory format
    phishing_samples = _load_dir(data_dir / "phishing", label=1)
    legit_samples = _load_dir(data_dir / "legitimate", label=0)

    if balance and max_samples:
        n = min(max_samples // 2, len(phishing_samples), len(legit_samples))
        phishing_samples = phishing_samples[:n]
        legit_samples = legit_samples[:n]
    elif max_samples:
        half = max_samples // 2
        phishing_samples = phishing_samples[:half]
        legit_samples = legit_samples[:half]

    all_samples = phishing_samples + legit_samples
    logger.info(
        f"Loaded {len(phishing_samples)} phishing + {len(legit_samples)} legitimate "
        f"= {len(all_samples)} total samples."
    )
    return all_samples


def _load_dir(directory: Path, label: int) -> list[WebsiteSample]:
    samples = []
    if not directory.exists():
        logger.warning(f"Directory not found: {directory}")
        return samples

    url_files = sorted(directory.glob("*.url"))
    for url_file in url_files:
        sample_id = url_file.stem
        html_file = url_file.with_suffix(".html")
        if not html_file.exists():
            continue
        url = url_file.read_text(encoding="utf-8", errors="replace").strip()
        raw_html = html_file.read_text(encoding="utf-8", errors="replace")
        sample = preprocess_sample(url, raw_html, label=label, sample_id=sample_id)
        if sample:
            samples.append(sample)

    return samples


def _load_csv(
    csv_path: Path,
    max_samples: Optional[int] = None,
    balance: bool = True,
) -> list[WebsiteSample]:
    phishing, legitimate = [], []
    with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            url = row.get("url", row.get("URL", "")).strip()
            raw_html = row.get("html", row.get("HTML", row.get("content", ""))).strip()
            raw_label = row.get("label", row.get("Label", row.get("class", "1"))).strip()
            label = int(raw_label) if raw_label.isdigit() else (1 if "phish" in raw_label.lower() else 0)

            sample = preprocess_sample(url, raw_html, label=label, sample_id=str(i))
            if sample:
                (phishing if label == 1 else legitimate).append(sample)

    if balance and max_samples:
        n = min(max_samples // 2, len(phishing), len(legitimate))
        phishing, legitimate = phishing[:n], legitimate[:n]
    elif max_samples:
        half = max_samples // 2
        phishing, legitimate = phishing[:half], legitimate[:half]

    all_samples = phishing + legitimate
    logger.info(
        f"CSV loaded: {len(phishing)} phishing + {len(legitimate)} legitimate "
        f"= {len(all_samples)} samples."
    )
    return all_samples


def load_samples_from_json(json_path: str) -> list[WebsiteSample]:
    """
    Load pre-processed samples from a JSON file produced by `save_samples_to_json`.
    Useful for caching the preprocessing step.
    """
    with open(json_path, encoding="utf-8") as f:
        records = json.load(f)
    return [
        WebsiteSample(
            url=r["url"],
            html=r["html"],
            text=r["text"],
            label=r["label"],
            sample_id=r.get("sample_id", ""),
        )
        for r in records
    ]


def save_samples_to_json(samples: list[WebsiteSample], json_path: str) -> None:
    """Save preprocessed samples to JSON for reuse."""
    records = [
        {
            "url": s.url,
            "html": s.html,
            "text": s.text,
            "label": s.label,
            "sample_id": s.sample_id,
        }
        for s in samples
    ]
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)
    logger.info(f"Saved {len(samples)} samples to {json_path}")
