"""
PhishDebate Agent Implementations
Four Specialist Agents + Moderator + Judge
"""

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Optional

from .prompts import (
    URL_ANALYST_SYSTEM, URL_ANALYST_TEMPLATE,
    HTML_STRUCTURE_SYSTEM, HTML_STRUCTURE_TEMPLATE,
    CONTENT_SEMANTIC_SYSTEM, CONTENT_SEMANTIC_TEMPLATE,
    BRAND_IMPERSONATION_SYSTEM, BRAND_IMPERSONATION_TEMPLATE,
    DEBATE_ROUND_TEMPLATE,
    MODERATOR_SYSTEM, MODERATOR_TEMPLATE,
    JUDGE_SYSTEM, JUDGE_TEMPLATE,
)
from .llm_client import LLMClient

logger = logging.getLogger(__name__)


@dataclass
class AgentResponse:
    agent_name: str
    claim: str          # "PHISHING" | "LEGITIMATE" | "UNCERTAIN"
    confidence: float
    evidence: str
    raw_text: str
    position_changed: bool = False
    round_num: int = 1


@dataclass
class ModeratorResponse:
    consensus_reached: bool
    supported_assessment: str   # "PHISHING" | "LEGITIMATE" | "UNCERTAIN"
    reasoning: str
    confidence: float
    continue_debate: bool
    round_num: int


@dataclass
class JudgeResponse:
    assessment: str     # "PHISHING" | "LEGITIMATE"
    confidence: float
    reasoning: str
    key_evidence: list


# ─────────────────────────────────────────────
# Parsing helpers
# ─────────────────────────────────────────────

def _parse_claim(text: str) -> tuple[str, float, str]:
    """
    Parse the bullet-point response format used by specialist agents:
      - Claim: PHISHING
      - Confidence: 0.87
      - Evidence: ...
    Returns (claim, confidence, evidence).
    """
    claim = "UNCERTAIN"
    confidence = 0.5
    evidence = ""

    claim_match = re.search(r"-\s*Claim\s*:\s*(.+)", text, re.IGNORECASE)
    if claim_match:
        raw = claim_match.group(1).strip().upper()
        if "PHISHING" in raw:
            claim = "PHISHING"
        elif "LEGITIMATE" in raw or "LEGIT" in raw or "BENIGN" in raw:
            claim = "LEGITIMATE"

    conf_match = re.search(r"-\s*Confidence\s*:\s*([0-9.]+)", text, re.IGNORECASE)
    if conf_match:
        try:
            confidence = float(conf_match.group(1).strip())
            confidence = max(0.0, min(1.0, confidence))
        except ValueError:
            pass

    ev_match = re.search(r"-\s*Evidence\s*:\s*(.+)", text, re.IGNORECASE | re.DOTALL)
    if ev_match:
        # Grab until the next bullet or end
        evidence = re.split(r"\n-\s+", ev_match.group(1))[0].strip()

    return claim, confidence, evidence


def _parse_position_change(text: str) -> bool:
    match = re.search(r"-\s*Position Change\s*:\s*(YES|NO)", text, re.IGNORECASE)
    if match:
        return match.group(1).upper() == "YES"
    return False


# ─────────────────────────────────────────────
# Specialist Agents
# ─────────────────────────────────────────────

class SpecialistAgent:
    def __init__(self, name: str, system_prompt: str, template: str, client: LLMClient):
        self.name = name
        self.system_prompt = system_prompt
        self.template = template
        self.client = client

    def analyze(
        self,
        url: str,
        html: str,
        text: str,
        round_num: int = 1,
        previous_analyses: Optional[str] = None,
    ) -> AgentResponse:
        """Run the agent for a given round."""
        if round_num == 1:
            user_prompt = self.template.format(url=url, html=html, text=text)
            response_text = self.client.chat(self.system_prompt, user_prompt)
            claim, confidence, evidence = _parse_claim(response_text)
            return AgentResponse(
                agent_name=self.name,
                claim=claim,
                confidence=confidence,
                evidence=evidence,
                raw_text=response_text,
                round_num=round_num,
            )
        else:
            # Debate round — agent sees other agents' analyses
            debate_prompt = DEBATE_ROUND_TEMPLATE.format(
                url=url,
                html=html,
                text=text,
                previous_analyses=previous_analyses or "",
                agent_role=self.name,
            )
            response_text = self.client.chat(self.system_prompt, debate_prompt)
            claim, confidence, evidence = _parse_claim(response_text)
            position_changed = _parse_position_change(response_text)
            return AgentResponse(
                agent_name=self.name,
                claim=claim,
                confidence=confidence,
                evidence=evidence,
                raw_text=response_text,
                position_changed=position_changed,
                round_num=round_num,
            )


def build_specialist_agents(client: LLMClient) -> dict[str, SpecialistAgent]:
    return {
        "URL Analyst": SpecialistAgent(
            name="URL Analyst Agent",
            system_prompt=URL_ANALYST_SYSTEM,
            template=URL_ANALYST_TEMPLATE,
            client=client,
        ),
        "HTML Structure": SpecialistAgent(
            name="HTML Structure Agent",
            system_prompt=HTML_STRUCTURE_SYSTEM,
            template=HTML_STRUCTURE_TEMPLATE,
            client=client,
        ),
        "Content Semantic": SpecialistAgent(
            name="Content Semantic Agent",
            system_prompt=CONTENT_SEMANTIC_SYSTEM,
            template=CONTENT_SEMANTIC_TEMPLATE,
            client=client,
        ),
        "Brand Impersonation": SpecialistAgent(
            name="Brand Impersonation Agent",
            system_prompt=BRAND_IMPERSONATION_SYSTEM,
            template=BRAND_IMPERSONATION_TEMPLATE,
            client=client,
        ),
    }


# ─────────────────────────────────────────────
# Coordination Agents
# ─────────────────────────────────────────────

class ModeratorAgent:
    def __init__(self, client: LLMClient, consensus_threshold: float = 0.75):
        self.client = client
        self.consensus_threshold = consensus_threshold

    def evaluate(
        self, agent_responses: list[AgentResponse], round_num: int
    ) -> ModeratorResponse:
        analyses_text = self._format_analyses(agent_responses)
        user_prompt = MODERATOR_TEMPLATE.format(
            round_num=round_num,
            analyses=analyses_text,
        )
        raw = self.client.chat(MODERATOR_SYSTEM, user_prompt)
        parsed = self.client.parse_json(raw)

        consensus_reached = parsed.get("consensus_reached", False)
        confidence = float(parsed.get("confidence", 0.5))

        # Enforce confidence threshold
        if consensus_reached and confidence < self.consensus_threshold:
            consensus_reached = False

        return ModeratorResponse(
            consensus_reached=consensus_reached,
            supported_assessment=parsed.get("supported_assessment", "UNCERTAIN"),
            reasoning=parsed.get("reasoning", ""),
            confidence=confidence,
            continue_debate=parsed.get("continue_debate", not consensus_reached),
            round_num=round_num,
        )

    @staticmethod
    def _format_analyses(responses: list[AgentResponse]) -> str:
        lines = []
        for r in responses:
            lines.append(
                f"[{r.agent_name}] Round {r.round_num}\n"
                f"  Claim: {r.claim}\n"
                f"  Confidence: {r.confidence:.2f}\n"
                f"  Evidence: {r.evidence[:300]}…\n"
            )
        return "\n".join(lines)


class JudgeAgent:
    def __init__(self, client: LLMClient):
        self.client = client

    def judge(
        self,
        all_responses: list[AgentResponse],
        moderator_eval: ModeratorResponse,
        total_rounds: int,
    ) -> JudgeResponse:
        analyses_by_round: dict[int, list[AgentResponse]] = {}
        for r in all_responses:
            analyses_by_round.setdefault(r.round_num, []).append(r)

        all_text_parts = []
        for rnd in sorted(analyses_by_round):
            all_text_parts.append(f"=== Round {rnd} ===")
            for resp in analyses_by_round[rnd]:
                all_text_parts.append(
                    f"[{resp.agent_name}] {resp.claim} (confidence {resp.confidence:.2f})\n"
                    f"Evidence: {resp.evidence[:400]}"
                )

        moderator_text = (
            f"Consensus reached: {moderator_eval.consensus_reached}\n"
            f"Assessment: {moderator_eval.supported_assessment}\n"
            f"Confidence: {moderator_eval.confidence:.2f}\n"
            f"Reasoning: {moderator_eval.reasoning}"
        )

        user_prompt = JUDGE_TEMPLATE.format(
            total_rounds=total_rounds,
            all_analyses="\n".join(all_text_parts),
            moderator_evaluation=moderator_text,
        )
        raw = self.client.chat(JUDGE_SYSTEM, user_prompt)
        parsed = self.client.parse_json(raw)

        assessment = parsed.get("assessment", "UNCERTAIN").upper()
        if assessment not in ("PHISHING", "LEGITIMATE"):
            # Fallback: majority vote from last round
            last_round = max(analyses_by_round.keys())
            claims = [r.claim for r in analyses_by_round[last_round]]
            assessment = (
                "PHISHING"
                if claims.count("PHISHING") >= len(claims) / 2
                else "LEGITIMATE"
            )

        return JudgeResponse(
            assessment=assessment,
            confidence=float(parsed.get("confidence", 0.5)),
            reasoning=parsed.get("reasoning", ""),
            key_evidence=parsed.get("key_evidence", []),
        )
