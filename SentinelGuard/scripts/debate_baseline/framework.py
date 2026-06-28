"""
PhishDebate: Main Framework Orchestrator
Implements Algorithm 1 from the paper (4-phase debate loop).
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from .agents.agents import (
    SpecialistAgent, ModeratorAgent, JudgeAgent,
    AgentResponse, ModeratorResponse, JudgeResponse,
    build_specialist_agents,
)
from .agents.llm_client import LLMClient

logger = logging.getLogger(__name__)


@dataclass
class PhishDebateResult:
    # Final decision
    assessment: str          # "PHISHING" | "LEGITIMATE"
    confidence: float
    label: int               # 1 = PHISHING, 0 = LEGITIMATE

    # Debate metadata
    total_rounds: int
    early_termination: bool
    consensus_reached: bool

    # Agent details
    all_agent_responses: list[AgentResponse] = field(default_factory=list)
    moderator_history: list[ModeratorResponse] = field(default_factory=list)
    judge_response: Optional[JudgeResponse] = None

    # Timing
    elapsed_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "assessment": self.assessment,
            "confidence": self.confidence,
            "label": self.label,
            "total_rounds": self.total_rounds,
            "early_termination": self.early_termination,
            "consensus_reached": self.consensus_reached,
            "elapsed_seconds": self.elapsed_seconds,
            "judge_reasoning": self.judge_response.reasoning if self.judge_response else "",
            "key_evidence": self.judge_response.key_evidence if self.judge_response else [],
        }


class PhishDebate:
    """
    PhishDebate multi-agent debate framework for phishing website detection.

    Parameters
    ----------
    client : LLMClient
        LLM backend client.
    max_rounds : int
        Maximum debate rounds (paper evaluates Rmax = 1 to 3).
    consensus_threshold : float
        Minimum moderator confidence to trigger early termination.
    active_agents : list[str] | None
        Subset of ["URL Analyst", "HTML Structure", "Content Semantic", "Brand Impersonation"].
        None = use all four.
    html_token_limit : int
        Truncate HTML to this character limit to respect context windows.
    text_token_limit : int
        Truncate visible text to this character limit.
    """

    AGENT_NAMES = [
        "URL Analyst",
        "HTML Structure",
        "Content Semantic",
        "Brand Impersonation",
    ]
    REQUIRED_AGENTS = {"Moderator", "Judge"}  # Cannot be excluded

    def __init__(
        self,
        client: LLMClient,
        max_rounds: int = 2,
        consensus_threshold: float = 0.75,
        active_agents: Optional[list[str]] = None,
        html_token_limit: int = 8000,
        text_token_limit: int = 3000,
    ):
        self.client = client
        self.max_rounds = max_rounds
        self.consensus_threshold = consensus_threshold
        self.html_token_limit = html_token_limit
        self.text_token_limit = text_token_limit

        # Validate & set active specialists
        if active_agents is None:
            self.active_agents = list(self.AGENT_NAMES)
        else:
            invalid = [a for a in active_agents if a not in self.AGENT_NAMES]
            if invalid:
                raise ValueError(f"Unknown agents: {invalid}. Valid: {self.AGENT_NAMES}")
            if len(active_agents) < 1:
                raise ValueError("At least one specialist agent must be active.")
            self.active_agents = active_agents

        # Build agents
        all_specialists = build_specialist_agents(client)
        self.specialists: dict[str, SpecialistAgent] = {
            k: v for k, v in all_specialists.items() if k in self.active_agents
        }
        self.moderator = ModeratorAgent(client, consensus_threshold=consensus_threshold)
        self.judge = JudgeAgent(client)

        logger.info(
            f"PhishDebate initialized | model={client.model} | "
            f"max_rounds={max_rounds} | agents={self.active_agents}"
        )

    # ─────────────────────────────────────────
    # Core detect method
    # ─────────────────────────────────────────

    def detect(self, url: str, html: str, text: str) -> PhishDebateResult:
        """
        Run the full PhishDebate debate pipeline on one website sample.

        Parameters
        ----------
        url  : The website URL string.
        html : Cleaned HTML source (script/style tags removed).
        text : Visible text content extracted from the HTML.
        """
        t0 = time.time()

        # Content truncation (preserve structural integrity)
        html = self._truncate(html, self.html_token_limit, is_html=True)
        text = self._truncate(text, self.text_token_limit, is_html=False)

        all_responses: list[AgentResponse] = []
        moderator_history: list[ModeratorResponse] = []
        consensus_reached = False
        round_num = 1

        # ── Phase 1: Initial Analysis (Round 1) ───────────────────────────────
        logger.debug("Phase 1: Independent analysis — Round 1")
        round_responses = self._run_specialists(url, html, text, round_num=1)
        all_responses.extend(round_responses)

        # ── Phase 2: Consensus Evaluation ────────────────────────────────────
        mod_eval = self.moderator.evaluate(round_responses, round_num=1)
        moderator_history.append(mod_eval)
        logger.debug(
            f"Moderator Round 1: consensus={mod_eval.consensus_reached}, "
            f"assessment={mod_eval.supported_assessment}, conf={mod_eval.confidence:.2f}"
        )

        if mod_eval.consensus_reached:
            consensus_reached = True
            logger.debug("Early termination after Round 1 — consensus reached.")
        else:
            # ── Phase 3: Multi-round Debate (Rounds 2+) ──────────────────────
            for round_num in range(2, self.max_rounds + 1):
                if consensus_reached:
                    break

                logger.debug(f"Phase 3: Debate Round {round_num}")
                context = self._format_context(all_responses)
                round_responses = self._run_specialists(
                    url, html, text, round_num=round_num, previous_analyses=context
                )
                all_responses.extend(round_responses)

                mod_eval = self.moderator.evaluate(round_responses, round_num=round_num)
                moderator_history.append(mod_eval)
                logger.debug(
                    f"Moderator Round {round_num}: consensus={mod_eval.consensus_reached}, "
                    f"assessment={mod_eval.supported_assessment}, conf={mod_eval.confidence:.2f}"
                )

                if mod_eval.consensus_reached:
                    consensus_reached = True
                    break

        # ── Phase 4: Final Judgment ───────────────────────────────────────────
        judge_result = self.judge.judge(
            all_responses=all_responses,
            moderator_eval=moderator_history[-1],
            total_rounds=round_num,
        )
        logger.debug(
            f"Judge: {judge_result.assessment} (confidence {judge_result.confidence:.2f})"
        )

        elapsed = time.time() - t0

        return PhishDebateResult(
            assessment=judge_result.assessment,
            confidence=judge_result.confidence,
            label=1 if judge_result.assessment == "PHISHING" else 0,
            total_rounds=round_num,
            early_termination=consensus_reached and round_num < self.max_rounds,
            consensus_reached=consensus_reached,
            all_agent_responses=all_responses,
            moderator_history=moderator_history,
            judge_response=judge_result,
            elapsed_seconds=elapsed,
        )

    # ─────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────

    def _run_specialists(
        self,
        url: str,
        html: str,
        text: str,
        round_num: int,
        previous_analyses: Optional[str] = None,
    ) -> list[AgentResponse]:
        responses = []
        for agent_key, agent in self.specialists.items():
            try:
                resp = agent.analyze(
                    url=url,
                    html=html,
                    text=text,
                    round_num=round_num,
                    previous_analyses=previous_analyses,
                )
                responses.append(resp)
                logger.debug(
                    f"  [{agent_key}] Round {round_num}: {resp.claim} ({resp.confidence:.2f})"
                )
            except Exception as e:
                logger.error(f"Agent {agent_key} failed: {e}")
        return responses

    @staticmethod
    def _format_context(responses: list[AgentResponse]) -> str:
        """Format all previous responses as debate context for next round."""
        parts = []
        for r in responses:
            parts.append(
                f"[{r.agent_name}] Round {r.round_num} — {r.claim} (conf {r.confidence:.2f})\n"
                f"Evidence: {r.evidence}"
            )
        return "\n\n".join(parts)

    @staticmethod
    def _truncate(content: str, char_limit: int, is_html: bool) -> str:
        """Truncate content to char_limit, preserving HTML tag boundaries."""
        if len(content) <= char_limit:
            return content

        if is_html:
            # Truncate at tag boundary
            truncated = content[:char_limit]
            last_tag = max(truncated.rfind(">"), truncated.rfind("<"))
            if last_tag > char_limit * 0.8:
                truncated = truncated[: last_tag + 1]
            return truncated + "\n<!-- [TRUNCATED FOR TOKEN LIMIT] -->"
        else:
            return content[:char_limit] + "\n[... content truncated ...]"
