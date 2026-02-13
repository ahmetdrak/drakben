# core/intelligence/react_loop.py
# DRAKBEN — ReAct (Reasoning + Acting) Loop
# Tight Observe → Think → Act cycle where the LLM decides EVERY step
# based on real tool output, not a pre-written plan.
#
# Key difference from the old linear plan:
#   OLD: Plan 5 steps → execute all blindly
#   NEW: LLM sees each tool output → decides next step dynamically
#
# Reference: Yao et al. "ReAct: Synergizing Reasoning and Acting in LLMs"

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.agent.brain import DrakbenBrain
    from core.agent.state import AgentState
    from core.execution.execution_engine import ExecutionEngine
    from core.execution.tool_selector import ToolSelector
    from core.intelligence.evolution_memory import EvolutionMemory

logger = logging.getLogger(__name__)


class ReActAction(Enum):
    """Possible actions the ReAct loop can take."""

    TOOL = "tool"          # Execute a tool
    THINK = "think"        # Internal reasoning (no tool)
    FINISH = "finish"      # Goal achieved
    ESCALATE = "escalate"  # Needs human input


@dataclass
class Thought:
    """Single reasoning step in the ReAct loop."""

    step: int
    reasoning: str           # LLM's chain-of-thought
    action: ReActAction
    tool: str = ""           # Tool to execute (if action == TOOL)
    tool_args: dict = field(default_factory=dict)
    confidence: float = 0.5
    final_answer: str = ""   # Set when action == FINISH


@dataclass
class Observation:
    """Result of executing a tool — fed back to LLM."""

    tool: str
    output: str              # Raw stdout (truncated)
    success: bool
    duration: float = 0.0
    structured: dict = field(default_factory=dict)  # Parsed output


class ReActLoop:
    """Tight Observe → Think → Act loop.

    Instead of generating a full plan up front, the LLM decides
    ONE step at a time, sees the result, and then decides the next step.

    Usage::

        loop = ReActLoop(brain, executor, tool_selector)
        result = loop.run(
            goal="Pentest 10.0.0.1",
            target="10.0.0.1",
            agent_state=state,
        )

    """

    # Safety limits
    MAX_STEPS = 30
    MAX_CONSECUTIVE_THINKS = 3   # Prevent infinite reasoning loops
    MAX_OBSERVATION_CHARS = 4000  # Token budget per observation
    MAX_HISTORY_IN_PROMPT = 8    # How many past steps to include in prompt

    def __init__(
        self,
        brain: DrakbenBrain,
        executor: ExecutionEngine | None = None,
        tool_selector: ToolSelector | None = None,
        evolution: EvolutionMemory | None = None,
        *,
        max_steps: int = 30,
        verbose: bool = True,
    ) -> None:
        self.brain = brain
        self.executor = executor
        self.tool_selector = tool_selector
        self.evolution = evolution
        self._max_steps = min(max_steps, self.MAX_STEPS)
        self.verbose = verbose

        # Loop state
        self.thoughts: list[Thought] = []
        self.observations: list[Observation] = []
        self.step_count: int = 0
        self._consecutive_thinks: int = 0

    def run(
        self,
        goal: str,
        target: str,
        agent_state: AgentState | None = None,
        available_tools: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute the full ReAct loop until FINISH or step limit.

        Args:
            goal: High-level objective (e.g., "Pentest 10.0.0.1")
            target: Target IP/domain
            agent_state: Current agent state for context
            available_tools: List of tool names the LLM can choose from

        Returns:
            Dict with final_answer, steps taken, observations collected

        """
        self.thoughts.clear()
        self.observations.clear()
        self.step_count = 0
        self._consecutive_thinks = 0

        if available_tools is None:
            available_tools = self._get_available_tools()

        for step in range(1, self._max_steps + 1):
            self.step_count = step

            # 1. THINK — Ask LLM what to do next
            thought = self._think(goal, target, agent_state, available_tools)
            self.thoughts.append(thought)

            if thought.action == ReActAction.FINISH:
                logger.info("ReAct loop finished at step %d: %s", step, thought.final_answer[:100])
                return self._build_result(thought.final_answer, success=True)

            if thought.action == ReActAction.ESCALATE:
                return self._build_result(
                    thought.reasoning, success=False, escalated=True,
                )

            if thought.action == ReActAction.THINK:
                self._consecutive_thinks += 1
                if self._consecutive_thinks >= self.MAX_CONSECUTIVE_THINKS:
                    logger.warning("ReAct: Too many consecutive thinks, forcing tool use")
                    # Don't break — next iteration the prompt will push for action
                continue

            # 2. ACT — Execute the tool
            self._consecutive_thinks = 0
            observation = self._act(thought, target, agent_state)
            self.observations.append(observation)

            # 3. OBSERVE — Feed result back to brain
            if self.brain:
                self.brain.observe(
                    tool=observation.tool,
                    output=observation.output,
                    success=observation.success,
                )

        # Step limit reached
        return self._build_result(
            "Step limit reached without completing the goal.",
            success=False,
        )

    def _think(
        self,
        goal: str,
        target: str,
        agent_state: AgentState | None,
        available_tools: list[str],
    ) -> Thought:
        """Ask LLM to reason about the next action.

        The prompt includes:
        - Goal and target
        - Available tools
        - Recent observation history
        - Agent state summary

        """
        prompt = self._build_think_prompt(goal, target, agent_state, available_tools)
        system_prompt = self._build_system_prompt()

        # Query LLM
        llm_client = getattr(self.brain, "llm_client", None)
        if not llm_client:
            return self._fallback_think(goal, target, agent_state)

        try:
            response = llm_client.query(prompt, system_prompt, timeout=30)
            return self._parse_thought(response, self.step_count)
        except Exception as e:
            logger.warning("ReAct think failed: %s", e)
            return self._fallback_think(goal, target, agent_state)

    def _act(
        self,
        thought: Thought,
        target: str,
        _agent_state: AgentState | None,
    ) -> Observation:
        """Execute the tool chosen by the LLM."""
        tool_name = thought.tool
        args = dict(thought.tool_args)
        args.setdefault("target", target)

        t0 = time.time()

        if not self.executor:
            return Observation(
                tool=tool_name,
                output="[Error] No executor available",
                success=False,
                duration=0.0,
            )

        try:
            result = self.executor.execute_tool(tool_name, args)
            duration = time.time() - t0

            stdout = result.get("stdout", "") if isinstance(result, dict) else str(result)
            success = result.get("success", False) if isinstance(result, dict) else False

            # Truncate output for token budget
            truncated = stdout[:self.MAX_OBSERVATION_CHARS]
            if len(stdout) > self.MAX_OBSERVATION_CHARS:
                truncated += f"\n... ({len(stdout) - self.MAX_OBSERVATION_CHARS} chars truncated)"

            # Update evolution penalties
            if self.evolution:
                self.evolution.update_penalty(tool_name, success=success, target=target)

            return Observation(
                tool=tool_name,
                output=truncated,
                success=success,
                duration=duration,
            )
        except Exception as e:
            duration = time.time() - t0
            return Observation(
                tool=tool_name,
                output=f"[Error] {e}",
                success=False,
                duration=duration,
            )

    def _build_system_prompt(self) -> str:
        """Build the system prompt for ReAct reasoning."""
        return (
            "You are DRAKBEN's ReAct reasoning engine. You think step-by-step "
            "and decide which tool to use based on observations.\n\n"
            "RESPONSE FORMAT (JSON only):\n"
            '{"thought": "your reasoning...", '
            '"action": "tool|think|finish|escalate", '
            '"tool": "tool_name_if_action_is_tool", '
            '"tool_args": {"arg": "value"}, '
            '"confidence": 0.0-1.0, '
            '"final_answer": "only_if_action_is_finish"}\n\n'
            "RULES:\n"
            "- Choose ONE action per step\n"
            "- Use 'think' only when you need to reason without acting\n"
            "- Use 'finish' when the goal is achieved or enough info gathered\n"
            "- Use 'escalate' when you need human input\n"
            "- Always explain your reasoning in 'thought'\n"
            "- Base decisions on ACTUAL observations, not assumptions\n"
            "- Do NOT repeat a tool that already succeeded with same args\n"
        )

    def _build_think_prompt(
        self,
        goal: str,
        target: str,
        agent_state: AgentState | None,
        available_tools: list[str],
    ) -> str:
        """Build the user prompt with full context."""
        parts: list[str] = []

        # Goal
        parts.append(f"GOAL: {goal}")
        parts.append(f"TARGET: {target}")
        parts.append(f"STEP: {self.step_count}/{self._max_steps}")

        # Available tools
        tools_str = ", ".join(available_tools[:20])
        parts.append(f"\nAVAILABLE TOOLS: {tools_str}")

        # Agent state summary
        if agent_state:
            state_summary = self._summarize_state(agent_state)
            parts.append(f"\nCURRENT STATE:\n{state_summary}")

        # Observation history (recent N steps)
        if self.observations:
            parts.append("\nPREVIOUS OBSERVATIONS:")
            recent = self.observations[-self.MAX_HISTORY_IN_PROMPT:]
            for i, obs in enumerate(recent, 1):
                status = "✓" if obs.success else "✗"
                # Further truncate in prompt context
                output_preview = obs.output[:800]
                parts.append(
                    f"\n[Step {i}] {status} {obs.tool} ({obs.duration:.1f}s):\n{output_preview}",
                )

        # If too many thinks, push for action
        if self._consecutive_thinks >= 2:
            parts.append(
                "\n⚠️ You've been thinking without acting. "
                "Choose a tool to execute or finish.",
            )

        # Thought history (just the reasoning, not full observations)
        if self.thoughts:
            parts.append("\nYOUR PREVIOUS THOUGHTS:")
            for t in self.thoughts[-3:]:
                parts.append(f"  - [{t.action.value}] {t.reasoning[:150]}")

        parts.append("\nWhat is your next action? Respond in JSON.")
        return "\n".join(parts)

    def _summarize_state(self, agent_state: AgentState) -> str:
        """Create compact state summary for the LLM prompt."""
        lines: list[str] = []
        lines.append(f"Phase: {agent_state.phase.value}")
        lines.append(f"Target: {agent_state.target}")

        if agent_state.open_services:
            services = [
                f"{port}/{info.service}" if hasattr(info, "service") else str(port)
                for port, info in list(agent_state.open_services.items())[:10]
            ]
            lines.append(f"Open Services: {', '.join(services)}")

        if agent_state.vulnerabilities:
            vulns = [
                v.name if hasattr(v, "name") else str(v)
                for v in agent_state.vulnerabilities[:5]
            ]
            lines.append(f"Vulnerabilities: {', '.join(vulns)}")

        lines.append(f"Foothold: {'Yes' if agent_state.has_foothold else 'No'}")
        lines.append(f"Iterations: {agent_state.iteration_count}/{agent_state.max_iterations}")

        return "\n".join(lines)

    def _parse_thought(self, response: str, step: int) -> Thought:
        """Parse LLM response into a Thought object."""
        import re

        # Try JSON extraction
        json_match = re.search(r"```(?:json)?\s*(\{[^}]*\})\s*```", response, re.DOTALL)
        text = json_match.group(1) if json_match else response

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # Try finding raw JSON object
            obj_match = re.search(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", response, re.DOTALL)
            if obj_match:
                try:
                    data = json.loads(obj_match.group())
                except json.JSONDecodeError:
                    data = {}
            else:
                data = {}

        if not data:
            # LLM returned plain text — treat as a think step
            return Thought(
                step=step,
                reasoning=response[:500],
                action=ReActAction.THINK,
                confidence=0.3,
            )

        action_str = data.get("action", "think").lower().strip()
        action_map = {
            "tool": ReActAction.TOOL,
            "think": ReActAction.THINK,
            "finish": ReActAction.FINISH,
            "escalate": ReActAction.ESCALATE,
        }
        action = action_map.get(action_str, ReActAction.THINK)

        return Thought(
            step=step,
            reasoning=data.get("thought", data.get("reasoning", "")),
            action=action,
            tool=data.get("tool", ""),
            tool_args=data.get("tool_args", {}),
            confidence=min(max(float(data.get("confidence", 0.5)), 0.0), 1.0),
            final_answer=data.get("final_answer", ""),
        )

    def _fallback_think(
        self,
        _goal: str,
        _target: str,
        agent_state: AgentState | None,
    ) -> Thought:
        """Deterministic fallback when LLM is unavailable."""
        # Use the tool_selector's deterministic logic
        if self.tool_selector and agent_state:
            recommendation = self.tool_selector.recommend_next_action(agent_state)
            if recommendation:
                _, tool_name, args = recommendation
                return Thought(
                    step=self.step_count,
                    reasoning=f"LLM offline — deterministic selection: {tool_name}",
                    action=ReActAction.TOOL,
                    tool=tool_name,
                    tool_args=args,
                    confidence=0.6,
                )

        # No tools available — finish
        return Thought(
            step=self.step_count,
            reasoning="No LLM and no deterministic recommendation available",
            action=ReActAction.FINISH,
            final_answer="Cannot proceed without LLM or tool recommendations",
            confidence=0.1,
        )

    def _get_available_tools(self) -> list[str]:
        """Get list of available tool names from the tool selector."""
        if self.tool_selector and hasattr(self.tool_selector, "tools"):
            return list(self.tool_selector.tools.keys())
        # Default common tools
        return [
            "nmap_port_scan", "nmap_service_scan", "nmap_vuln_scan",
            "nikto_web_scan", "sqlmap_scan", "gobuster", "ffuf",
            "searchsploit", "hydra", "enum4linux", "passive_recon",
        ]

    def _build_result(
        self,
        final_answer: str,
        *,
        success: bool,
        escalated: bool = False,
    ) -> dict[str, Any]:
        """Build the final result dict."""
        return {
            "success": success,
            "final_answer": final_answer,
            "steps_taken": self.step_count,
            "thoughts": [
                {
                    "step": t.step,
                    "reasoning": t.reasoning,
                    "action": t.action.value,
                    "tool": t.tool,
                    "confidence": t.confidence,
                }
                for t in self.thoughts
            ],
            "observations": [
                {
                    "tool": o.tool,
                    "success": o.success,
                    "duration": o.duration,
                    "output_length": len(o.output),
                }
                for o in self.observations
            ],
            "escalated": escalated,
            "tools_used": list({o.tool for o in self.observations}),
        }

    def get_stats(self) -> dict[str, Any]:
        """Get loop statistics."""
        return {
            "total_steps": self.step_count,
            "total_thoughts": len(self.thoughts),
            "total_observations": len(self.observations),
            "tools_used": list({o.tool for o in self.observations}),
            "success_rate": (
                sum(1 for o in self.observations if o.success) / len(self.observations)
                if self.observations
                else 0.0
            ),
        }
