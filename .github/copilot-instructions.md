# Copilot instructions

## Big picture architecture
- Entry point is drakben.py which initializes core/agent.py.
- Agent flow: core/agent.py -> core/brain.py -> core/execution_engine.py -> core/security_toolkit.py.
- Optional async CLI lives in core/cli.py.
- Execution is event-driven: core/events.py emits step_* and notify_user; core/approval_flow.py is a one-time approval gate.
- Plugin contracts live in core/plugins/base.py; implementations are async execute() returning PluginResult.

## Plugin system conventions
- Plugin metadata/specs are loaded from config/plugins.json via PluginRegistry.load_from_file().
- No-op adapters in core/plugins/adapters/noop.py are placeholders; missing modules resolve to PluginNotAvailable.
- PluginKind values live in core/plugins/base.py: recon/analysis/exploit/payload/bypass/post.

## i18n and CLI conventions
- CLI strings go through core/i18n.py via t(key, lang) with DEFAULT_LANG="tr".
- core/cli.py supports: lang <tr/en>, target <value>, plan <intent>, run, approve, plugins, status.

## Workflows & testing
- Primary run: python drakben.py (see README.md/INSTALLATION.md for platform specifics).
- Tests use pytest with markers in pytest.ini; common run: pytest -v (testpaths=tests).

## External integration points
- Optional LLM providers configured in config/api.env (copied from .env.example).
- Optional pentest toolchain (nmap/sqlmap/etc.) used by legacy paths in the entry script; treat as best-effort on non-Kali systems.
