# Changelog

All notable changes to DRAKBEN will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned
- Real-time WebSocket dashboard for live attack monitoring
- Plugin marketplace with community contributions
- Automated report generation with executive summary
- Multi-target campaign management

---

## [2.5.0] - 2026-02-13

### Added — Intelligence v2 (Reasoning Pipeline)
- **ReAct Loop** (`core/intelligence/react_loop.py`) — Thought→Action→Observation reasoning cycle for structured multi-step LLM reasoning with iteration tracking
- **Structured Output Parser** (`core/intelligence/structured_output.py`) — Multi-strategy parser extracting JSON, tables, key-value pairs from raw LLM text with fallback chains
- **Tool Output Analyzer** (`core/intelligence/tool_output_analyzer.py`) — Classifies tool results (success/partial/fail), extracts IPs, ports, CVEs, URLs from output text
- **Context Compressor** (`core/intelligence/context_compressor.py`) — Token-aware conversation history compression with priority scoring and budget management
- **Self-Reflection Engine** (`core/intelligence/self_reflection.py`) — Post-action reflection with confidence scoring, lesson extraction, and improvement suggestions

### Added — Intelligence v3 (Advanced AI Modules)
- **Few-Shot Engine** (`core/intelligence/few_shot_engine.py`) — Dynamic few-shot example selection from past successes for in-context learning with similarity matching
- **Cross-Tool Correlator** (`core/intelligence/cross_correlator.py`) — Pattern recognition across tool outputs: port↔CVE mapping, service↔vulnerability correlation, multi-source evidence aggregation
- **Adversarial Adapter** (`core/intelligence/adversarial_adapter.py`) — WAF/IDS evasion payload generator with encoding mutations (URL, Unicode, hex, double-encode), technique-specific bypass strategies
- **Exploit Predictor** (`core/intelligence/exploit_predictor.py`) — ML-style probability scoring for exploit success based on service fingerprints, version analysis, and historical patterns
- **Knowledge Base** (`core/intelligence/knowledge_base.py`) — SQLite-backed cross-session knowledge store with semantic recall, deduplication, and context-aware retrieval
- **Model Router** (`core/intelligence/model_router.py`) — Intelligent LLM model selection based on task complexity, token budget, and provider capabilities

### Added — Architecture & Infrastructure
- **EventBus** (`core/events.py`) — Thread-safe publish/subscribe event system with pause/resume and history tracking
- **Observability** (`core/observability.py`) — Distributed tracing with Tracer/Span, MetricsCollector with p50/p95/p99 statistics
- **KnowledgeGraph** (`core/knowledge_graph.py`) — SQLite-backed graph database for attack topology, BFS path finding, JSON export
- **ToolDispatcher** (`core/agent/tool_dispatch.py`) — Centralized tool routing with error isolation and structured results
- **MultiAgentCoordinator** (`core/agent/multi_agent.py`) — Parallel agent orchestration with task distribution
- **WebAPI** (`core/ui/web_api.py`) — RESTful API layer for external integrations (traces, metrics, events)
- **CloudScanner** (`modules/cloud_scanner.py`) — AWS/GCP/Azure misconfiguration detection (S3 buckets, IAM, metadata)

### Added — LLM Infrastructure
- **LLMEngine** (`core/llm/llm_engine.py`) — Unified LLM interface with caching, retry, and provider abstraction
- **TokenCounter** (`core/llm/token_counter.py`) — Accurate token counting per model with tiktoken integration
- **MultiTurnManager** (`core/llm/multi_turn.py`) — Conversation history with sliding window and token budget
- **OutputValidator** (`core/llm/output_models.py`) — Pydantic-based structured output validation with auto-repair
- **RAGPipeline** (`core/llm/rag_pipeline.py`) — Retrieval-Augmented Generation with context ranking
- **AsyncLLMClient** (`core/llm/async_client.py`) — Non-blocking LLM calls with connection pooling

### Added — Exploit Module Expansion
- **Injection Module** (`modules/exploit/injection.py`) — Advanced SQL injection (error-based, time-based, UNION), NoSQL injection (MongoDB), LDAP injection, OS command injection with 5+ DBMS signature detection
- **Auth Bypass Module** (`modules/exploit/auth_bypass.py`) — JWT token manipulation (none algo, algorithm confusion, claim tampering), session fixation detection, 20+ default credential sets, privilege escalation path scanning
- **Header Security Module** (`modules/exploit/header_security.py`) — HTTP security header audit with scoring (A-F grading), CORS misconfiguration detection, CSP bypass analysis, host header injection, clickjacking detection
- **File Inclusion Module** (`modules/exploit/file_inclusion.py`) — Advanced LFI with PHP wrappers (filter, input, data, phar), RFI testing, path traversal with encoding bypass, file upload bypass (8 techniques), log poisoning for LFI→RCE

### Added — Testing & Quality
- **E2E Integration Tests** (`tests/test_e2e_integration.py`) — 40+ end-to-end tests covering cross-module interaction flows: Config→Agent bootstrap, EventBus→KG pipeline, State→Exploit preconditions, Memory→Cognitive cycle, full pentest simulation, multi-agent coordination, thread safety validation
- **Exploit Module Tests** (`tests/test_exploit_modules.py`) — 50+ tests for new exploit sub-modules: DBMS detection, JWT analysis, CSP analysis, file content detection, payload generation
- **Architecture Tests** (`tests/test_architecture_improvements.py`) — 93 tests for new architecture components

### Changed — Quality Improvements
- **Mypy strict mode** — Reduced disabled error codes from 12 to 3. Added `disallow_untyped_defs`, `disallow_untyped_calls`, `check_untyped_defs` for 11 core modules. Enabled `warn_return_any`, `warn_unreachable`, `strict_equality`, `warn_redundant_casts`
- **GitHub Actions CI** — Enhanced with dependency caching, Python 3.11/3.12/3.13 matrix, ruff + bandit + mypy pipeline, coverage upload to Codecov, SonarCloud integration
- **GitHub Actions CD** — Tag-triggered release pipeline with auto-changelog, GitHub Release creation, Docker Hub multi-tag push

### Fixed — 16 Bug Fixes
- **K05**: KnowledgeGraph `find_attack_paths()` BFS returns empty for self-referencing nodes
- **K06**: EventBus `_paused` flag race condition in `publish()` — now checked inside lock
- **K08**: Observability p95 off-by-one on arrays of length < 20
- **K11**: ToolDispatcher `args` could be `None` — added `args = args or {}` guard
- **K12**: WebAPI `asyncio.Queue()` unbounded — now capped at `maxsize=1000`
- **K13**: KnowledgeGraph `_connect()` returns wrong mode for `:memory:` DBs
- **K14**: MultiAgentCoordinator `_total_tokens` dead state accumulation removed
- **K15**: KnowledgeGraph `add_edge()` silently fails when source/target nodes don't exist
- **K16**: `_NoOpSpan` missing `duration_ms` property and `to_dict()` — added both
- **K18**: KnowledgeGraph `get_edges()` crashes on empty graph without `edges` table
- **K19**: KnowledgeGraph `export_json()` doesn't close file-based DB connections
- **K20**: `Span.to_dict()` infinite recursion on deeply nested spans — max depth 50
- **N2**: KnowledgeGraph connection leak — added `_get_conn()` auto-close context manager
- **N5**: CloudScanner `scan_target()` session leak — added `try/finally` cleanup
- **N7**: WebAPI `/api/v1/traces` unbounded limit — capped at `min(limit, 500)`
- **N8**: `_NoOpSpan.children` shared mutable class attribute — changed to `@property`

### Changed — Code Quality Pass
- **SonarQube** — 55+ issues resolved to zero: Cognitive Complexity refactoring across `brain.py` (40→8), `refactored_agent.py` (3 methods split), `llm_engine.py` (27→8), `cross_correlator.py` (10 methods), `brain_reasoning.py`, `structured_output.py`, `few_shot_engine.py`, `knowledge_base.py`. Unused params prefixed with `_`, regex patterns optimized, field naming conflicts resolved, duplicate string literals extracted to constants
- **Ruff** — 21 issues resolved: I001 import sorting (4 files), PLW0211 `cls` rename, Q000 quote consistency, COM812 trailing commas (4 fixes), F401 unused imports removed, B007/PERF102 loop variable optimizations, FURB171 single-item membership. Final: "All checks passed!"
- **Test Suite** — Expanded from 1363 to 1609+ tests (all passing, 0 failures, 0 skips)

### Security — Hardening
- **LLMConfig API Key Removal** — `openrouter_api_key: str | None` and `openai_api_key: str | None` fields replaced with `openrouter_key_set: bool` / `openai_key_set: bool` boolean flags. Raw API keys no longer stored in config dataclass (CodeQL: clear-text credentials)
- **WebAPI Exception Exposure** — `web_api.py` error responses replaced with generic "Internal server error" messages instead of exposing exception details (CodeQL: information exposure)
- **Password Logging Redaction** — `exploit/common.py` password values redacted with `****` in log output (CodeQL: clear-text logging)

---

## [2.0.0] - 2026-02-07

### Added — Core Framework
- **Stanford Memory System** — Graph-based memory with semantic search and ChromaDB vector store
- **Self-Refining Engine** — Policy engine, conflict resolution, failure context analysis, automatic replanning
- **Singularity Engine** — AST-based code synthesis with 7 real templates, polymorphic mutation, AST security gates
- **Advanced WAF Bypass Engine** — Intelligent fingerprinting (Cloudflare, AWS WAF, ModSecurity, Imperva, Akamai, F5 BIG-IP), multi-layer encoding, adaptive mutation with SQLite memory
- **NVD CVE Integration** — `fetch_and_prepare_exploit()` with 5-CVE deep analysis and CVSS scoring
- **Boundary-Aware Symbolic Executor** — Heuristic constraint solver with per-operator dispatch for vulnerability discovery
- **C2 Framework** — Domain fronting, DNS tunneling, AES-256-GCM encrypted beacons, Telegram C2, steganography, DoH transport
- **Hive Mind** — Distributed operations, network topology discovery, BloodHound-style pathfinding
- **Active Directory Attacks** — Kerberoasting, AS-REP Roasting, DCSync, Pass-the-Hash, Pass-the-Ticket, lateral movement
- **Weapon Foundry** — Multi-format payloads (Python, PowerShell, VBS, HTA, Bash, C#), multi-layer encryption
- **Ghost Protocol** — AST-based code transformation, variable obfuscation, dead code injection, string encryption
- **Sandbox Execution** — Docker isolation with resource limits and automatic cleanup
- **DoH C2 Transport** — DNS over HTTPS for covert C2 communication
- **Auto-Pivoting** — TunnelManager and AutoPivot for automatic lateral movement
- **Real SMTP Phishing** — `smtplib.SMTP` with STARTTLS and MIME multipart construction
- **Systemd Persistence** — Real user-level systemd service unit installation
- **Error Diagnostics** — Advanced error analysis (18+ patterns) and recovery suggestions in TR/EN

### Added — UI & UX
- **Interactive Shell** — Full REPL with readline, tab completion, command history, 15+ built-in commands
- **Bilingual i18n** — Complete Turkish (`/tr`) and English (`/en`) support
- **Dracula Theme** — Minimalist Cyan/Green terminal color scheme via Rich
- **Real-time Scanning** — Live progress indicators with spinner and status updates
- **Smart Confirmations** — Context-aware prompts for high-risk operations

### Added — Testing
- Tool Registry with 30+ built-in tools
- Pentest Orchestrator with state machine (RECON → VULN_SCAN → EXPLOIT → FOOTHOLD → POST_EXPLOIT → COMPLETE)
- 1330+ tests passing with comprehensive coverage

### Changed
- **Architecture Overhaul** — MasterOrchestrator (Brain) split into cognitive modules: `brain_reasoning.py`, `brain_decision.py`, `brain_orchestrator.py`, `brain_self_correction.py`
- **UI Modernization** — Minimalist unified display with consistent theming
- `modules/exploit/` refactored from single file to package with `common.py` + `__init__.py`
- Ruff expanded to 35+ rule groups (all passing, zero issues)
- Python 3.11 / 3.12 / 3.13 support

### Security
- **CommandSanitizer** — 30+ forbidden command patterns, regex-based detection, risk levels
- Forbidden command blocking with SecurityError exceptions
- High-risk operation confirmation prompts
- SSL verification configurable per-connection
- Anti-sandbox detection for security testing environments
- AST security gates in Singularity code generation

---

## [1.5.0] - 2026-01-15

### Added
- **Cognitive Memory Architecture** — Perceive → Retrieve → Reflect cycle based on Stanford Generative Agents
- **Evolution Memory** — Persistent learning across sessions with tool penalty system
- **Strategy Profiles** — Multiple behavioral variants per attack type with automatic adaptation
- **Failure Context Analysis** — Pattern recognition from error contexts
- **Plugin System** — JSON-manifested plugin loading from `config/plugins.json`
- **ConfigManager** — Thread-safe centralized configuration with TimeoutConfig
- **Structured Logging** — JSON-formatted logs with context and severity levels

### Changed
- Agent state migrated to thread-safe singleton pattern
- LLM client updated with connection pooling and TTL cache
- Recon module made fully async with `aiohttp` and exponential backoff

### Fixed
- Race condition in AgentState when accessed from multiple threads
- Memory leak in ChromaDB vector store connection management
- Timeout handling in execution engine for long-running tools

---

## [1.0.0] - 2025-12-01

### Added
- **Initial Release** — Core autonomous penetration testing framework
- **AI Agent** — Natural language interface for security testing commands
- **Multi-LLM Support** — OpenRouter, Ollama, OpenAI API integration
- **Reconnaissance** — Port scanning (Nmap), service enumeration, WHOIS, DNS analysis
- **Web Testing** — SQL injection (SQLMap), XSS, LFI, SSRF, CSRF, SSTI, XXE, IDOR
- **Exploit Module** — Precondition-enforced exploitation with state awareness
- **Report Generation** — HTML, Markdown, JSON output with severity classification
- **Docker Support** — Kali Rolling base image with pre-installed security tools
- **CLI Interface** — Rich-based terminal with colored output

### Security
- API key management via environment variables
- No hardcoded credentials
- Placeholder detection for unset API keys

---

[unreleased]: https://github.com/ahmetdrak/drakben/compare/v2.5.0...HEAD
[2.5.0]: https://github.com/ahmetdrak/drakben/compare/v2.0.0...v2.5.0
[2.0.0]: https://github.com/ahmetdrak/drakben/compare/v1.5.0...v2.0.0
[1.5.0]: https://github.com/ahmetdrak/drakben/compare/v1.0.0...v1.5.0
[1.0.0]: https://github.com/ahmetdrak/drakben/releases/tag/v1.0.0
