# core/planner.py
# REAL PERSISTENT PLANNER WITH REPLANNING
# Plans are DATA STRUCTURES, not LLM-only

import json
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any

from core.evolution_memory import get_evolution_memory


class StepStatus(Enum):
    PENDING = "pending"
    EXECUTING = "executing"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class PlanStep:
    """Single step in a plan"""

    step_id: str
    action: str  # Action type: scan, exploit, etc.
    tool: str  # Tool to use
    target: str  # Target for this step
    params: dict  # Additional parameters
    depends_on: list[str]  # Step IDs this depends on
    status: StepStatus
    max_retries: int
    retry_count: int
    expected_outcome: str  # What we expect to happen
    actual_outcome: str  # What actually happened
    error: str


class Planner:
    """
    STRATEGY-DRIVEN PLANNER

    Plans are created FROM STRATEGIES, not hardcoded.

    LOOP PROTECTION:
    - Maximum replan attempts per step
    - Global replan limit per session
    """

    # Replan limits to prevent infinite loops
    MAX_REPLAN_PER_STEP = 3  # Maximum replans for a single step
    MAX_REPLAN_PER_SESSION = 10  # Maximum total replans per session

    # Action to tool mapping
    ACTION_TO_TOOL = {
        "port_scan": "nmap_port_scan",
        "service_scan": "nmap_service_scan",
        "vuln_scan": "nmap_vuln_scan",
        "web_vuln_scan": "nikto_web_scan",
        "sqlmap_exploit": "sqlmap_scan",
        "xss_test": "xss_scanner",
        "passive_recon": "passive_recon",
        "manual_review": "manual_review",
        "exploit_search": "searchsploit",
        "api_discovery": "api_discovery",
        "param_fuzzing": "param_fuzzer",
        "auth_bypass_test": "auth_bypass",
        "db_enum": "db_enum",
        "credential_test": "credential_test",
        "data_exfil": "data_exfil",
    }

    def __init__(self):
        self.memory = get_evolution_memory()
        self.current_plan_id: str | None = None
        self.steps: list[PlanStep] = []
        self.current_step_index: int = 0
        self.current_strategy_name: str | None = None

    def create_plan_from_strategy(
        self, target: str, strategy: Any, goal: str = "pentest"
    ) -> str:
        """
        Create a plan FROM A STRATEGY.
        Strategy determines the steps, not hardcoded logic.

        Args:
            target: Target IP/URL to scan
            strategy: Strategy object with steps and parameters
            goal: Plan goal description (default: "pentest")

        Returns:
            plan_id: Unique identifier for the created plan

        Behavior:
            - Converts strategy steps to PlanStep objects
            - Persists plan to evolution memory
            - Sets as current plan for execution
        """
        plan_id = self._generate_plan_id()
        self.current_strategy_name = strategy.name

        steps = self._build_strategy_steps(strategy, plan_id, target)

        # Initialize and Persist
        self._save_and_load_plan(plan_id, goal, steps)

        return plan_id

    def _build_strategy_steps(self, strategy, plan_id: str, target: str) -> list[dict]:
        """Helper to build steps from strategy objects"""
        steps = []
        for i, action in enumerate(strategy.steps):
            tool = self.ACTION_TO_TOOL.get(action, action)
            step = self._create_step_dict(plan_id, i, action, tool, target)
            steps.append(step)
        return steps

    def _create_step_dict(
        self, plan_id: str, index: int, action: str, tool: str, target: str
    ) -> dict:
        """Create a single step dictionary structure"""
        return {
            "step_id": f"{plan_id}_step_{index + 1}",
            "action": action,
            "tool": tool,
            "target": target,
            "params": {},
            "depends_on": [f"{plan_id}_step_{index}"] if index > 0 else [],
            "status": StepStatus.PENDING.value,
            "max_retries": 2,
            "retry_count": 0,
            "expected_outcome": f"complete_{action}",
            "actual_outcome": "",
            "error": "",
        }

    def _save_and_load_plan(self, plan_id: str, goal: str, steps: list[dict]):
        """Persist plan to memory and load into local state"""
        self.memory.create_plan(goal, steps, plan_id=plan_id)
        self.current_plan_id = plan_id
        self.steps = [self._dict_to_step(s) for s in steps]
        self.current_step_index = 0

    def _generate_plan_id(self) -> str:
        return f"plan_{uuid.uuid4().hex[:8]}"

    # ... (other create_plan methods refactored similarly if needed) ...

    def replan(self, failed_step_id: str) -> bool:
        """
        Replan after failure with ADAPTIVE LEARNING.
        Facade method that delegates to specialized helpers.

        Args:
            failed_step_id: ID of the step that failed

        Returns:
            True if replanning succeeded, False if limits exceeded

        LOOP PROTECTION:
        - Tracks replan count per step
        - Tracks global replan count per session
        - Refuses to replan if limits exceeded
        """
        # Initialize replan tracking if needed
        # (Already initialized in __init__, but kept for robustness)
        if not hasattr(self, "_replan_counts"):
            self._replan_counts: dict[str, int] = {}
        if not hasattr(self, "_total_replans"):
            self._total_replans = 0

        step = self._find_step(failed_step_id)
        if step is None:
            return False

        # Check replan limits
        step_replan_count = self._replan_counts.get(failed_step_id, 0)

        if step_replan_count >= self.MAX_REPLAN_PER_STEP:
            import logging

            logging.getLogger(__name__).warning(
                f"Step {failed_step_id} exceeded replan limit ({step_replan_count}/{self.MAX_REPLAN_PER_STEP})"
            )
            return self._skip_step(
                step, f"Replan limit exceeded ({step_replan_count}x)"
            )

        if self._total_replans >= self.MAX_REPLAN_PER_SESSION:
            import logging

            logging.getLogger(__name__).warning(
                f"Session replan limit exceeded ({self._total_replans}/{self.MAX_REPLAN_PER_SESSION})"
            )
            return self._skip_step(
                step, f"Session replan limit exceeded ({self._total_replans}x)"
            )

        # Increment counters
        self._replan_counts[failed_step_id] = step_replan_count + 1
        self._total_replans += 1

        # 1. Analyze & Learn
        failure_context = self._analyze_failure(step)
        self._apply_adaptive_learning(step, failure_context)

        # 2. Attempt Strategy Shift
        if self._try_switch_tool(step, failure_context):
            return True

        # 3. Fallback
        return self._skip_step(step, "No alternative tool available")

    def _analyze_failure(self, step: PlanStep) -> dict:
        """Analyze why a step failed"""
        error_lower = step.error.lower()
        return {
            "is_timeout": "timeout" in error_lower or "timed out" in error_lower,
            "is_conn_refused": "connection refused" in error_lower,
            "is_missing": "not found" in error_lower or "missing" in error_lower,
            "original_tool": step.tool,
        }

    def _apply_adaptive_learning(self, step: PlanStep, context: dict):
        """Adjust system heuristics based on failure context"""
        if context["is_timeout"]:
            # Backend learning: Increase timeout tolerance
            self.memory.update_heuristic("default_timeout", lambda x: min(x * 1.5, 300))
            self.memory.update_heuristic("aggressiveness", lambda x: max(x - 0.2, 0.1))

            # Local adaptation: Boost this step's timeout
            step.params["timeout"] = 120

    def _try_switch_tool(self, step: PlanStep, context: dict) -> bool:
        """Try to find and switch to an alternative tool"""
        alternative = self._find_alternative_tool(step.action, step.tool, step.target)

        if not alternative:
            return False

        # Execute Switch
        step.tool = alternative
        step.status = StepStatus.PENDING
        step.retry_count = 0

        reason = self._format_replan_reason(context)
        step.error = f"{reason}Switched {context['original_tool']} -> {alternative}"

        self._persist_steps()
        self._penalize_tool()

        return True

    def _skip_step(self, step: PlanStep, reason: str) -> bool:
        """Mark step as skipped"""
        step.status = StepStatus.SKIPPED
        step.error = f"{reason}. Original error: {step.error}"
        self._persist_steps()
        return True

    def _format_replan_reason(self, context: dict) -> str:
        """Format human-readable reason for replan"""
        if context["is_timeout"]:
            return "Adaptive Replan: Timeout detected. "
        if context["is_missing"]:
            return "Adaptive Replan: Tool missing. "
        return "Adaptive Replan: "

    def _penalize_tool(self):
        """Increase penalty for a failed tool"""
        current = self.memory.get_heuristic("penalty_increment")
        self.memory.set_heuristic("penalty_increment", min(20.0, current + 1.0))

    def _generate_steps_from_profile(
        self, target: str, profile, plan_id: str
    ) -> list[dict]:
        """Helper to generate steps from profile config"""
        step_order = profile.step_order
        profile_params = profile.parameters
        aggressiveness = profile.aggressiveness

        # Map abstract phases to concrete actions based on aggressiveness
        phase_to_actions = {
            "recon": ["passive_recon"]
            if aggressiveness < 0.5
            else ["port_scan", "service_scan"],
            "scan": ["web_vuln_scan"]
            if aggressiveness < 0.3
            else ["vuln_scan", "web_vuln_scan"],
            "analyze": ["manual_review", "exploit_search"],
            "exploit": ["sqlmap_exploit"] if aggressiveness > 0.6 else ["xss_test"],
        }

        steps = []
        step_num = 0

        for phase in step_order:
            actions = phase_to_actions.get(phase, [phase])
            for action in actions:
                step_num += 1
                steps.append(
                    self._create_single_step_dict(
                        plan_id,
                        step_num,
                        action,
                        target,
                        profile_params,
                        aggressiveness,
                        profile.profile_id,
                    )
                )
        return steps

    def _create_single_step_dict(
        self,
        plan_id,
        step_num,
        action,
        target,
        profile_params,
        aggressiveness,
        profile_id,
    ):
        """Helper to create a single step dictionary"""
        tool = self.ACTION_TO_TOOL.get(action, action)

        # Apply profile parameters to step
        step_params = {}
        if "timeout" in profile_params:
            step_params["timeout"] = profile_params["timeout"]
        if "threads" in profile_params:
            step_params["threads"] = profile_params["threads"]
        if "parallel_scans" in profile_params:
            step_params["parallel"] = profile_params["parallel_scans"]

        return {
            "step_id": f"{plan_id}_step_{step_num}",
            "action": action,
            "tool": tool,
            "target": target,
            "params": step_params,
            "depends_on": [f"{plan_id}_step_{step_num - 1}"] if step_num > 1 else [],
            "status": StepStatus.PENDING.value,
            "max_retries": 3 if aggressiveness > 0.7 else 2,
            "retry_count": 0,
            "expected_outcome": f"complete_{action}",
            "actual_outcome": "",
            "error": "",
            "profile_id": profile_id,
        }

    def create_plan_for_target(self, target: str, goal: str = "pentest") -> str:
        """
        Create a plan for pentesting a target.
        Returns plan_id.

        This is a DETERMINISTIC plan based on attack phases.
        """
        plan_id = f"plan_{uuid.uuid4().hex[:8]}"

        # FIXED PLAN STRUCTURE - Not LLM generated
        steps = [
            {
                "step_id": f"{plan_id}_step_1",
                "action": "port_scan",
                "tool": "nmap_port_scan",
                "target": target,
                "params": {},
                "depends_on": [],
                "status": StepStatus.PENDING.value,
                "max_retries": 2,
                "retry_count": 0,
                "expected_outcome": "discover_open_ports",
                "actual_outcome": "",
                "error": "",
            },
            {
                "step_id": f"{plan_id}_step_2",
                "action": "service_scan",
                "tool": "nmap_service_scan",
                "target": target,
                "params": {},
                "depends_on": [f"{plan_id}_step_1"],
                "status": StepStatus.PENDING.value,
                "max_retries": 2,
                "retry_count": 0,
                "expected_outcome": "identify_services",
                "actual_outcome": "",
                "error": "",
            },
            {
                "step_id": f"{plan_id}_step_3",
                "action": "vuln_scan",
                "tool": "nmap_vuln_scan",
                "target": target,
                "params": {},
                "depends_on": [f"{plan_id}_step_2"],
                "status": StepStatus.PENDING.value,
                "max_retries": 2,
                "retry_count": 0,
                "expected_outcome": "find_vulnerabilities",
                "actual_outcome": "",
                "error": "",
            },
            {
                "step_id": f"{plan_id}_step_4",
                "action": "exploit",
                "tool": "sqlmap_scan",
                "target": target,
                "params": {},
                "depends_on": [f"{plan_id}_step_3"],
                "status": StepStatus.PENDING.value,
                "max_retries": 1,
                "retry_count": 0,
                "expected_outcome": "exploit_vulnerability",
                "actual_outcome": "",
                "error": "",
            },
        ]

        # Store in persistent memory
        self.memory.create_plan(goal, steps, plan_id=plan_id)

        # Load into local state
        self.current_plan_id = plan_id
        self.steps = [self._dict_to_step(s) for s in steps]
        self.current_step_index = 0

        return plan_id

    def create_plan_from_profile(
        self, target: str, profile, goal: str = "pentest"
    ) -> str:
        """
        Create a plan from a StrategyProfile.

        Args:
            target: Target IP/URL
            profile: StrategyProfile object with step_order, parameters, aggressiveness
            goal: Goal identifier for the plan

        Returns:
            plan_id
        """
        import uuid

        plan_id = f"plan_{uuid.uuid4().hex[:8]}"

        # Generate steps from profile
        steps = self._generate_steps_from_profile(target, profile, plan_id)

        if not steps:
            # Fallback to default plan if no steps generated
            return self.create_plan_for_target(target, goal)

        # Store in persistent memory
        self.memory.create_plan(goal, steps, plan_id=plan_id)

        # Load into local state
        self.current_plan_id = plan_id
        self.steps = [self._dict_to_step(s) for s in steps]
        self.current_step_index = 0

        return plan_id

    def load_plan(self, plan_id: str) -> bool:
        """Load existing plan from memory"""
        plan_record = self.memory.get_plan(plan_id)
        if plan_record is None:
            return False

        self.current_plan_id = plan_id
        steps_data = json.loads(plan_record.steps)
        self.steps = [self._dict_to_step(s) for s in steps_data]

        # Find first non-completed step
        for i, step in enumerate(self.steps):
            if step.status in [StepStatus.PENDING, StepStatus.FAILED]:
                self.current_step_index = i
                break

        return True

    def get_next_step(self) -> PlanStep | None:
        """
        Get next executable step from current plan.

        Returns:
            Next PlanStep ready for execution, or None if plan complete

        Selection Logic:
            - Skips completed/failed steps
            - Checks dependencies
            - Returns first executable step
        """
        """
        Get next step to execute.
        Checks dependencies and skips blocked tools.
        """
        for i in range(self.current_step_index, len(self.steps)):
            step = self.steps[i]

            # Skip completed/skipped
            if step.status in [StepStatus.SUCCESS, StepStatus.SKIPPED]:
                continue

            # LOGIC FIX: Check if tool is blocked by penalty system (Per-Target)
            if self.memory.is_tool_blocked(step.tool, step.target):
                step.status = StepStatus.SKIPPED
                step.error = f"Tool {step.tool} blocked for target {step.target} due to high penalty"
                self._persist_steps()
                continue

            # Check dependencies
            deps_satisfied = True
            for dep_id in step.depends_on:
                dep_step = self._find_step(dep_id)
                if dep_step and dep_step.status not in [
                    StepStatus.SUCCESS,
                    StepStatus.SKIPPED,
                ]:
                    deps_satisfied = False
                    break

            if not deps_satisfied:
                # LOGIC FIX: If a dependency FAILED (not skipped or success), 
                # this step should also be skipped to prevent deadlock.
                for dep_id in step.depends_on:
                    dep_step = self._find_step(dep_id)
                    if dep_step and dep_step.status == StepStatus.FAILED:
                        step.status = StepStatus.SKIPPED
                        step.error = f"Dependency {dep_id} failed. Skipping."
                        self._persist_steps()
                        deps_satisfied = False
                        break

            if deps_satisfied:
                self.current_step_index = i
                return step

        return None  # Plan complete

    def mark_step_executing(self, step_id: str):
        """Mark step as executing"""
        step = self._find_step(step_id)
        if step:
            step.status = StepStatus.EXECUTING
            self._persist_steps()

    def mark_step_success(self, step_id: str, outcome: str):
        """Mark step as successful"""
        step = self._find_step(step_id)
        if step:
            step.status = StepStatus.SUCCESS
            step.actual_outcome = outcome
            self._persist_steps()

            # Penalty updates handled by execution layer

    def mark_step_failed(self, step_id: str, error: str) -> bool:
        """
        Mark step as failed.
        Returns True if should replan, False if should retry.
        """
        step = self._find_step(step_id)
        if step is None:
            return False

        step.retry_count += 1
        step.error = error

        # Penalty updates handled by execution layer

        # Check if we should retry or replan
        if step.retry_count >= step.max_retries:
            step.status = StepStatus.FAILED
            self._persist_steps()
            return True  # Trigger replan
        else:
            step.status = StepStatus.PENDING  # Will retry
            self._persist_steps()
            return False

    # FIX: Removed duplicate replan() method - using the one defined at line 147

    def is_plan_complete(self) -> bool:
        """Check if plan is complete"""
        for step in self.steps:
            if step.status in [StepStatus.PENDING, StepStatus.EXECUTING]:
                return False
        return True

    def get_plan_status(self) -> dict:
        """Get current plan status"""
        return {
            "plan_id": self.current_plan_id,
            "total_steps": len(self.steps),
            "completed": sum(1 for s in self.steps if s.status == StepStatus.SUCCESS),
            "failed": sum(1 for s in self.steps if s.status == StepStatus.FAILED),
            "skipped": sum(1 for s in self.steps if s.status == StepStatus.SKIPPED),
            "pending": sum(1 for s in self.steps if s.status == StepStatus.PENDING),
            "current_step": self.current_step_index,
        }

    def _find_step(self, step_id: str) -> PlanStep | None:
        """Find step by ID"""
        for step in self.steps:
            if step.step_id == step_id:
                return step
        return None

    def _find_alternative_tool(self, action: str, failed_tool: str, target: str = "global") -> str | None:
        """Find alternative tool for action"""
        # Mapping of actions to alternative tools
        alternatives = {
            "port_scan": ["nmap_port_scan"],
            "service_scan": ["nmap_service_scan"],
            "vuln_scan": ["nmap_vuln_scan", "nikto_web_scan", "nuclei_scan"],
            "exploit": ["sqlmap_scan", "metasploit_exploit"],
            "ad_attack": ["ad_asreproast", "ad_smb_spray"],
        }

        candidates = alternatives.get(action, [])

        for tool in candidates:
            # LOGIC FIX: Target-aware alternative tool selection
            if tool != failed_tool and not self.memory.is_tool_blocked(tool, target):
                return tool

        return None

    def _persist_steps(self):
        """Save current steps to memory"""
        if self.current_plan_id:
            steps_data = [self._step_to_dict(s) for s in self.steps]
            self.memory.update_plan_steps(self.current_plan_id, steps_data)

    def _dict_to_step(self, d: dict) -> PlanStep:
        """Convert dict to PlanStep"""
        return PlanStep(
            step_id=d["step_id"],
            action=d["action"],
            tool=d["tool"],
            target=d["target"],
            params=d.get("params", {}),
            depends_on=d.get("depends_on", []),
            status=StepStatus(d.get("status", "pending")),
            max_retries=d.get("max_retries", 2),
            retry_count=d.get("retry_count", 0),
            expected_outcome=d.get("expected_outcome", ""),
            actual_outcome=d.get("actual_outcome", ""),
            error=d.get("error", ""),
        )

    def _step_to_dict(self, step: PlanStep) -> dict:
        """Convert PlanStep to dict"""
        return {
            "step_id": step.step_id,
            "action": step.action,
            "tool": step.tool,
            "target": step.target,
            "params": step.params,
            "depends_on": step.depends_on,
            "status": step.status.value,
            "max_retries": step.max_retries,
            "retry_count": step.retry_count,
            "expected_outcome": step.expected_outcome,
            "actual_outcome": step.actual_outcome,
            "error": step.error,
        }
