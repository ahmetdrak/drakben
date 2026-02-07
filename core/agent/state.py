# core/state.py
# DRAKBEN State Abstraction - SINGLE SOURCE OF TRUTH
# REQUIRED: All modules access/update state ONLY through this API
# Thread-safe implementation

import hashlib
import logging
import threading
import time
from dataclasses import asdict, dataclass
from enum import Enum
from threading import RLock
from typing import Optional, Self

# Setup logger
logger: logging.Logger = logging.getLogger(__name__)

# Constants
MAX_ITERATIONS = 15
MAX_INVARIANT_VIOLATIONS = 10
MAX_CONSECUTIVE_SAME_TOOL = 3
MAX_HALLUCINATION_FLAGS = 10
MAX_OBSERVATION_LENGTH = 500
MAX_TOOL_CALL_HISTORY = 10
MAX_STATE_CHANGES_HISTORY = 5
PHASE_TOLERANCE = 1
STAGNATION_CHECK_WINDOW = 3
MAX_HALLUCINATIONS_THRESHOLD = 3

# Thread-safe singleton implementation - MUST be defined BEFORE AgentState class
_state_lock: RLock = threading.RLock()
_state_instance: Optional["AgentState"] = None  # Forward reference


class AttackPhase(Enum):
    """Attack phases - deterministic flow."""

    INIT = "init"
    RECON = "recon"
    VULN_SCAN = "vulnerability_scan"
    EXPLOIT = "exploit"
    FOOTHOLD = "foothold"
    POST_EXPLOIT = "post_exploit"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass
class ServiceInfo:
    """Service information summary."""

    port: int
    protocol: str
    service: str
    version: str | None = None
    tested: bool = False
    vulnerable: bool = False
    exploit_attempted: bool = False


@dataclass
class CredentialInfo:
    """Credential information."""

    username: str
    service: str = ""
    password: str | None = None
    hash: str | None = None
    verified: bool = False


@dataclass
class VulnerabilityInfo:
    """Vulnerability information."""

    vuln_id: str
    service: str
    port: int
    severity: str  # low, medium, high, critical
    exploitable: bool
    exploit_attempted: bool = False
    exploit_success: bool = False


class AgentState:
    """DRAKBEN Agent State - SINGLE SOURCE OF TRUTH
    Thread-safe implementation with locking.

    Rules:
    1. All state updates through this class
    2. FORBIDDEN: Raw log, tool output, tool names
    3. ONLY: Meaningful summary, deterministic state
    4. validate() must be called after each update
    5. State pollution = SYSTEM HALT
    """

    def __new__(cls, *args, **kwargs) -> Self:
        """Ensure singleton instance."""
        global _state_instance
        if _state_instance is None:
            with _state_lock:
                if _state_instance is None:
                    # Create new instance and set global ref immediately
                    instance = super().__new__(cls)
                    _state_instance = instance
                    return instance
        return _state_instance

    def __init__(self, target: str | None = None) -> None:
        """Initialize agent state.

        Args:
            target: Target IP or domain (optional)

        """
        # Prevent re-initialization - CRITICAL: Don't wipe existing state!
        # Only allow target update if explicitly requested
        if getattr(self, "_initialized", False):
            # If already initialized, only update target if provided
            if target is not None:
                with self._lock:
                    self.target = target
            return

        # Thread safety lock - create ONCE per instance
        # Use _state_lock during init to prevent concurrent __init__ access
        with _state_lock:
            # Double-check after acquiring lock
            if getattr(self, "_initialized", False):
                if target is not None:
                    with self._lock:
                        self.target = target
                return

            self._lock: RLock = threading.RLock()

            # Core state
            self.target: str | None = target
            self.phase: AttackPhase = AttackPhase.INIT
            self.iteration_count: int = 0
            self.max_iterations: int = MAX_ITERATIONS

            # Mark as initialized BEFORE populating state
            self._initialized = True

            # Attack surface tracking
            self.open_services: dict[int, ServiceInfo] = {}  # port -> ServiceInfo
            self.tested_attack_surface: set[str] = set()  # "port:service" tuples
            self.remaining_attack_surface: set[str] = set()  # "port:service" tuples

            # Vulnerability tracking
            self.vulnerabilities: list[VulnerabilityInfo] = []

            # Credentials
            self.credentials: list[CredentialInfo] = []

            # Foothold state
            self.has_foothold: bool = False
            self.foothold_method: str | None = None
            self.foothold_timestamp: float | None = None

            # Post-exploit state
            self.post_exploit_completed: set[str] = set()

            # Execution tracking
            self.last_observation: str = ""  # Last tool observation (summary, not raw)
            self.state_changes_history: list[dict] = []  # Last state changes

            # Invariant violation tracking
            self.invariant_violations: list[str] = []
            self._max_invariant_violations: int = MAX_INVARIANT_VIOLATIONS

            # Agentic loop protection
            self.tool_call_history: list[str] = []  # Last tool calls
            self.last_state_hash: str = ""  # Last state hash
            self.consecutive_same_tool: int = 0  # Consecutive same tool count
            self.max_consecutive_same_tool: int = MAX_CONSECUTIVE_SAME_TOOL
            self.hallucination_flags: list[str] = []  # Hallucination warnings
            self._max_hallucination_flags: int = MAX_HALLUCINATION_FLAGS

    def clear(self, new_target: str | None = None) -> None:
        """Clear state for new run - preserves singleton reference.

        Args:
            new_target: New target IP or domain (optional)

        Use this instead of reset_state() to avoid breaking existing references.
        """
        with self._lock:
            # Core state
            self.target = new_target
            self.phase = AttackPhase.INIT
            self.iteration_count = 0

            # Attack surface tracking
            self.open_services.clear()
            self.tested_attack_surface.clear()
            self.remaining_attack_surface.clear()

            # Vulnerability tracking
            self.vulnerabilities.clear()

            # Credentials - secure wipe attempt
            for cred in self.credentials:
                if cred.password:
                    try:
                        from core.security.ghost_protocol import get_ram_cleaner
                        get_ram_cleaner().register_sensitive(cred.password)
                    except Exception as e:
                        logger.debug("RAMCleaner unavailable: %s", e)  # Optional, continue cleanup
            self.credentials.clear()

            # Foothold state
            self.has_foothold = False
            self.foothold_method = None
            self.foothold_timestamp = None

            # Post-exploit state
            self.post_exploit_completed.clear()

            # Execution tracking
            self.last_observation = ""
            self.state_changes_history.clear()

            # Invariant violation tracking
            self.invariant_violations.clear()

            # Agentic loop protection
            self.tool_call_history.clear()
            self.last_state_hash = ""
            self.consecutive_same_tool = 0
            self.hallucination_flags.clear()

    def __del__(self) -> None:
        """Securely wipe sensitive data from memory on destruction."""
        try:
            if hasattr(self, "credentials"):
                for cred in self.credentials:
                    if cred.password:
                        try:
                            # Best effort: overwrite reference
                            cred.password = "*" * len(cred.password)
                        except (TypeError, AttributeError):
                            pass
                self.credentials.clear()
        except Exception:
            pass  # During shutdown, logger may not be available

    def snapshot(self) -> dict:
        """Get state snapshot for LLM context.

        Returns:
            Dict with summarized state information

        """
        with self._lock:
            return {
                "target": self.target,
                "phase": self.phase.value,
                "iteration": f"{self.iteration_count}/{self.max_iterations}",
                "open_services_count": len(self.open_services),
                "tested_count": len(self.tested_attack_surface),
                "remaining_count": len(self.remaining_attack_surface),
                "vulnerabilities_count": len(self.vulnerabilities),
                "has_foothold": self.has_foothold,
                "last_observation": self.last_observation[:200],
            }

    def update_services(self, services: list[ServiceInfo]) -> None:
        """Update state after service discovery - SMART MERGE.
        Updates with more specific/detailed info, preserves existing.

        Args:
            services: List of ServiceInfo objects discovered

        Behavior:
            - Merges new services with existing ones
            - Prefers versioned info over unknown
            - Preserves tested/vulnerable flags
            - Thread-safe operation

        """
        with self._lock:
            self._update_services_internal(services)

    def _update_services_internal(self, services: list[ServiceInfo]) -> None:
        """Internal method for update_services (not thread-safe, call with lock).

        Args:
            services: List of discovered services

        """
        for svc in services:
            self._merge_service(svc)
            self._add_to_attack_surface(svc)

        self._record_change("services_discovered", len(services))

    def _merge_service(self, svc: ServiceInfo) -> None:
        """Merge a service into open_services with smart rules."""
        if svc.port not in self.open_services:
            self.open_services[svc.port] = svc
            return

        existing: ServiceInfo = self.open_services[svc.port]
        if self._should_skip_unknown_service(svc, existing):
            return

        self.open_services[svc.port] = self._select_best_service(svc, existing)

    def _should_skip_unknown_service(
        self,
        svc: ServiceInfo,
        existing: ServiceInfo,
    ) -> bool:
        """Rule 1: Don't overwrite known service with 'unknown'."""
        return svc.service in ["unknown", "tcpwrapped"] and existing.service not in [
            "unknown",
            "tcpwrapped",
        ]

    def _select_best_service(
        self,
        svc: ServiceInfo,
        existing: ServiceInfo,
    ) -> ServiceInfo:
        """Rule 2: Prefer versioned info, then better service name."""
        if svc.version and not existing.version:
            return svc
        if not svc.version and existing.version:
            # Keep existing if it has version and new doesn't
            return existing
        if svc.service not in ("unknown", existing.service):
            # Prefer new service if it's better identified
            return svc
        # Default: keep existing service
        return existing

    def _add_to_attack_surface(self, svc: ServiceInfo) -> None:
        """Add service to attack surface if not tested."""
        surface_key: str = f"{svc.port}:{self.open_services[svc.port].service}"
        if surface_key not in self.tested_attack_surface:
            self.remaining_attack_surface.add(surface_key)

    def mark_surface_tested(self, port: int, service: str) -> None:
        """Mark an attack surface as tested.

        Args:
            port: Port number
            service: Service name

        """
        with self._lock:
            service_name = service
            if port in self.open_services:
                service_name = self.open_services[port].service
            surface_key: str = f"{port}:{service_name}"
            self.tested_attack_surface.add(surface_key)
            self.remaining_attack_surface.discard(surface_key)

            if port in self.open_services:
                self.open_services[port].tested = True

            self._record_change("surface_tested", surface_key)

    def add_vulnerability(self, vuln: VulnerabilityInfo) -> None:
        """Record discovered vulnerability.

        Args:
            vuln: Vulnerability information

        """
        with self._lock:
            self.vulnerabilities.append(vuln)

            if vuln.port in self.open_services:
                self.open_services[vuln.port].vulnerable = True

            self._record_change("vulnerability_found", vuln.vuln_id)

    def set_foothold(self, method: str) -> None:
        """Record foothold achievement.

        Args:
            method: Method used to achieve foothold

        """
        with self._lock:
            self.has_foothold = True
            self.foothold_method = method
            self.foothold_timestamp = time.time()
            self.phase = AttackPhase.FOOTHOLD

            self._record_change("foothold_achieved", method)

    def set_observation(self, observation: str) -> None:
        """Record last observation (max 500 chars).

        Args:
            observation: Observation text

        """
        with self._lock:
            self.last_observation = observation[:MAX_OBSERVATION_LENGTH]

    def increment_iteration(self) -> None:
        """Increment iteration count."""
        with self._lock:
            self._record_change("iteration", self.iteration_count + 1)
            self.iteration_count += 1

    # ============ AGENTIC LOOP PROTECTION ============

    def record_tool_call(self, tool_name: str) -> None:
        """Record tool call and check for repetition.

        Args:
            tool_name: Name of called tool

        """
        with self._lock:  # THREAD SAFETY: Add lock for consistent state access
            self.tool_call_history.append(tool_name)
            if len(self.tool_call_history) > MAX_TOOL_CALL_HISTORY:
                self.tool_call_history = self.tool_call_history[-MAX_TOOL_CALL_HISTORY:]

            if len(self.tool_call_history) >= 2:
                if self.tool_call_history[-1] == self.tool_call_history[-2]:
                    self.consecutive_same_tool += 1
                else:
                    self.consecutive_same_tool = 0

    def compute_state_hash(self) -> str:
        """Compute hash for state summary.

        Returns:
            8-character hash string

        """
        with self._lock:
            state_str: str = (
                f"{self.phase.value}|{len(self.open_services)}|"
                f"{len(self.tested_attack_surface)}|{len(self.remaining_attack_surface)}|"
                f"{len(self.vulnerabilities)}|{self.has_foothold}"
            )
            return hashlib.sha256(state_str.encode()).hexdigest()[:8]

    def check_state_changed(self) -> bool:
        """Check if state has changed.

        Returns:
            True if state changed, False otherwise

        """
        with self._lock:  # THREAD SAFETY: Add lock for consistent state access
            current_hash: str = self.compute_state_hash()
            if current_hash == self.last_state_hash:
                return False
            self.last_state_hash = current_hash
            return True

    def check_hallucination(
        self,
        tool_name: str,
        exit_code: int,
        stdout: str,
        claimed_success: bool,
    ) -> bool:
        """Hallucination check - LLM claims 'success' but is it really?

        Args:
            tool_name: Name of the tool
            exit_code: Exit code from execution
            stdout: Standard output
            claimed_success: Whether LLM claimed success

        Returns:
            True if hallucination detected, False if OK

        """
        # Rule 1: Exit code != 0 but success claimed
        if exit_code != 0 and claimed_success:
            self.hallucination_flags.append(
                f"{tool_name}: claimed success but exit_code={exit_code}",
            )
            return True

        # Rule 2: Exploit claimed successful but no shell
        if "exploit" in tool_name.lower() and claimed_success:
            if "shell" not in stdout.lower() and "session" not in stdout.lower():
                self.hallucination_flags.append(
                    f"{tool_name}: claimed exploit success but no shell/session in output",
                )
                return True

        # Rule 3: SQLi claimed but no confirmation in output
        if "sql" in tool_name.lower() and claimed_success:
            if "vulnerable" not in stdout.lower() and "injection" not in stdout.lower():
                self.hallucination_flags.append(
                    f"{tool_name}: claimed SQLi but no confirmation in output",
                )
                return True

        return False

    def is_tool_allowed_for_phase(self, tool_phase: str) -> bool:
        """Check if tool is allowed in current phase.

        Args:
            tool_phase: Phase the tool belongs to

        Returns:
            True if allowed, False otherwise

        """
        phase_order: dict[str, int] = {
            "init": 0,
            "recon": 1,
            "vulnerability_scan": 2,
            "exploit": 3,
            "foothold": 4,
            "post_exploit": 5,
            "complete": 6,
            "failed": 6,
        }

        current_order: int = phase_order.get(self.phase.value, 0)
        tool_order: int = phase_order.get(tool_phase, 0)

        # Tool can run in its phase or one phase after
        return tool_order <= current_order + PHASE_TOLERANCE

    def require_precondition(self, precondition: str) -> bool:
        """Check precondition.

        Args:
            precondition: Precondition string

        Returns:
            True if precondition met, False otherwise

        Examples:
            - 'port_22_open' -> Is port 22 open?
            - 'has_vulnerability' -> At least 1 vuln?
            - 'has_foothold' -> Foothold achieved?

        """
        if precondition == "has_foothold":
            return self.has_foothold
        if precondition == "has_vulnerability":
            return len(self.vulnerabilities) > 0
        if precondition == "has_services":
            return len(self.open_services) > 0
        if precondition.startswith("port_") and precondition.endswith("_open"):
            try:
                port = int(precondition.split("_")[1])
                return port in self.open_services
            except (ValueError, IndexError):
                return False
        return True  # Unknown precondition = allow

    def get_available_attack_surface(self) -> list[str]:
        """Get untested attack surfaces.

        Returns:
            List of "port:service" strings

        """
        return list(self.remaining_attack_surface)

    def should_halt(self) -> tuple[bool, str]:
        """Check if system should halt.

        Returns:
            Tuple of (should_halt, reason)

        """
        with self._lock:  # THREAD SAFETY: Consistent state access
            # Max iteration
            if self.iteration_count >= self.max_iterations:
                return True, "Max iteration reached"

            # Invariant violation
            if self.invariant_violations:
                return True, f"Invariant violation: {self.invariant_violations[0]}"

            # State stagnation check
            if len(self.state_changes_history) >= STAGNATION_CHECK_WINDOW:
                last_changes = self.state_changes_history[-STAGNATION_CHECK_WINDOW:]
                if all(c.get("type") == "iteration" for c in last_changes):
                    return True, "State stagnation detected"

            # Agentic loop: Same tool called consecutively
            if self.consecutive_same_tool >= self.max_consecutive_same_tool:
                return (
                    True,
                    f"Same tool called {self.consecutive_same_tool} times consecutively",
                )

            # Agentic loop: No targets left but still scanning
            if (
                self.phase in [AttackPhase.RECON, AttackPhase.VULN_SCAN]
                and len(self.remaining_attack_surface) == 0
                and len(self.open_services) > 0
                and self.iteration_count > 5
            ):
                return True, "No remaining attack surface but still scanning"

            # Success check
            if self.phase == AttackPhase.COMPLETE:
                return True, "Attack complete"

            if self.phase == AttackPhase.FAILED:
                return True, "Attack failed"

            return False, ""

    def validate(self) -> bool:
        """State invariant check - MUST BE CALLED AT END OF EVERY LOOP.

        Returns:
            True if valid, False if invariant violated

        """
        with self._lock:
            violations = []
            violations.extend(self._check_foothold_invariant())
            violations.extend(self._check_exploit_invariants())
            violations.extend(self._check_iteration_invariant())
            violations.extend(self._check_surface_invariants())
            violations.extend(self._check_limits_invariants())

            if violations:
                self.invariant_violations.extend(violations)
                logger.error("State invariant violations: %s", violations)
                return False
            return True

    def _check_foothold_invariant(self) -> list[str]:
        """Check foothold-related invariants."""
        violations = []
        if not self.has_foothold and self.post_exploit_completed:
            violations.append("Post-exploit attempted without foothold")
        return violations

    def _check_exploit_invariants(self) -> list[str]:
        """Check exploit phase invariants."""
        violations = []
        if self.phase == AttackPhase.EXPLOIT:
            if len(self.open_services) == 0:
                violations.append("Exploit phase without discovered services")
            if len(self.vulnerabilities) == 0:
                has_exploitable: bool = any(
                    svc.vulnerable for svc in self.open_services.values()
                )
                if not has_exploitable:
                    violations.append(
                        "Exploit phase without any vulnerabilities or exploitable services",
                    )
        return violations

    def _check_iteration_invariant(self) -> list[str]:
        """Check iteration count invariant."""
        violations = []
        if self.iteration_count > self.max_iterations:
            violations.append("Max iteration exceeded")
        return violations

    def _check_surface_invariants(self) -> list[str]:
        """Check attack surface invariants."""
        violations = []
        violations.extend(
            self._validate_surface_set(self.tested_attack_surface, "Tested"),
        )
        violations.extend(
            self._validate_surface_set(self.remaining_attack_surface, "Remaining"),
        )
        return violations

    def _validate_surface_set(self, surface_set: set, prefix: str) -> list[str]:
        """Validate a surface set against open services."""
        violations = []
        for surface in surface_set:
            port_str = surface.split(":")[0]
            try:
                port = int(port_str)
                if port not in self.open_services:
                    violations.append(
                        f"{prefix} surface {surface} not in open services",
                    )
            except ValueError:
                violations.append(f"Invalid {prefix.lower()} surface format: {surface}")
        return violations

    def _check_limits_invariants(self) -> list[str]:
        """Check limit-related invariants."""
        violations = []
        if len(self.hallucination_flags) >= MAX_HALLUCINATIONS_THRESHOLD:
            violations.append(
                f"Too many hallucinations detected ({len(self.hallucination_flags)})",
            )

        if self.consecutive_same_tool >= self.max_consecutive_same_tool:
            violations.append(
                f"Same tool called {self.consecutive_same_tool} times consecutively",
            )

        return violations

    def _record_change(self, change_type: str, data) -> None:
        """Record state change (last N changes).

        Args:
            change_type: Type of change
            data: Change data

        """
        change = {
            "type": change_type,
            "data": data,
            "iteration": self.iteration_count,
            "timestamp": time.time(),
        }
        self.state_changes_history.append(change)

        if len(self.state_changes_history) > MAX_STATE_CHANGES_HISTORY:
            self.state_changes_history = self.state_changes_history[
                -MAX_STATE_CHANGES_HISTORY:
            ]

    def to_dict(self) -> dict:
        """Convert full state to dict (for debug/logging).

        Returns:
            Dict representation of state

        """
        return {
            "target": self.target,
            "phase": self.phase.value,
            "iteration_count": self.iteration_count,
            "open_services": {k: asdict(v) for k, v in self.open_services.items()},
            "tested_attack_surface": list(self.tested_attack_surface),
            "remaining_attack_surface": list(self.remaining_attack_surface),
            "vulnerabilities": [asdict(v) for v in self.vulnerabilities],
            "credentials": [asdict(c) for c in self.credentials],
            "has_foothold": self.has_foothold,
            "foothold_method": self.foothold_method,
            "post_exploit_completed": list(self.post_exploit_completed),
            "state_changes_history": self.state_changes_history[
                -MAX_STATE_CHANGES_HISTORY:
            ],
            "invariant_violations": self.invariant_violations,
        }

    def from_dict(self, data: dict) -> None:
        """Load state from dict (for session recovery).

        Args:
            data: Dict representation of state

        """
        self.target = data.get("target")
        self.phase = AttackPhase(data.get("phase", "init"))
        self.iteration_count = data.get("iteration_count", 0)
        # Other fields as needed for future session recovery


# NOTE: _state_lock and _state_instance are defined at module top (before AgentState class)
# This ensures they're available when AgentState.__new__ is called


def reset_state(target: str | None = None) -> AgentState:
    """Reset state for new run (thread-safe).

    IMPORTANT: This clears the existing singleton instead of creating a new one.
    This preserves existing references to the state instance.

    Args:
        target: New target (optional)

    Returns:
        Same AgentState instance, cleared

    """
    global _state_instance
    with _state_lock:
        if _state_instance is None:
            _state_instance = AgentState(target)
        else:
            # Clear existing instance instead of creating new one
            # This preserves references held by other modules
            _state_instance.clear(target)
        return _state_instance
