# Contributing to DRAKBEN

Thank you for your interest in contributing to DRAKBEN! This document provides guidelines for contributing.

## 🔒 Important Notice

DRAKBEN is an **offensive security tool** designed for authorized penetration testing only. All contributions must:

1. Be legal and ethical
2. Not introduce malicious backdoors
3. Follow responsible disclosure practices
4. Include appropriate documentation

## Getting Started

### Prerequisites

- Python 3.13+
- Git
- Virtual environment (recommended)

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/drakben/drakben.git
cd drakben

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# or
.\.venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Run tests to verify setup
pytest --disable-warnings
```

## Code Standards

### Style Guide

We use the following tools for code quality:

- **Ruff** - Linting and formatting
- **Mypy** - Type checking
- **SonarQube** - Code quality analysis

Run all checks:

```bash
ruff check .
ruff format .
mypy .
```

### Type Annotations

All new code must include type annotations:

```python
def scan_target(target: str, ports: list[int] | None = None) -> dict[str, Any]:
    """Scan a target.
    
    Args:
        target: IP address or hostname
        ports: Optional list of ports (default: top 1000)
    
    Returns:
        Dictionary with scan results
    """
    ...
```

### Docstrings

Use Google-style docstrings:

```python
def function_name(param1: str, param2: int) -> bool:
    """Short description of function.

    Longer description if needed.

    Args:
        param1: Description of param1
        param2: Description of param2

    Returns:
        Description of return value

    Raises:
        ValueError: When param2 is negative
    """
```

## Testing

### Running Tests

```bash
# All tests
pytest

# Specific test file
pytest tests/test_recon.py

# With coverage
pytest --cov=. --cov-report=html

# Verbose output
pytest -v --tb=short
```

### Writing Tests

- Place tests in `tests/` directory
- Name test files `test_<module>.py`
- Use `pytest` fixtures from `conftest.py`
- Mock external dependencies (network, filesystem)

Example:

```python
# tests/test_mymodule.py
import pytest
from modules.mymodule import MyClass

class TestMyClass:
    def test_basic_functionality(self) -> None:
        """Test basic functionality."""
        obj = MyClass()
        result = obj.do_something()
        assert result == expected_value

    @pytest.mark.asyncio
    async def test_async_operation(self) -> None:
        """Test async operation."""
        obj = MyClass()
        result = await obj.async_method()
        assert result is not None
```

## Pull Request Process

### Before Submitting

1. **Create a branch**: `git checkout -b feature/my-feature`
2. **Write tests**: All new features need tests
3. **Run quality checks**:
   ```bash
   ruff check .
   ruff format .
   mypy .
   pytest
   ```
4. **Update documentation** if needed

### PR Guidelines

- Use descriptive commit messages
- Reference related issues
- Keep PRs focused (one feature per PR)
- Update CHANGELOG.md

### Commit Message Format

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance

Example:
```
feat(recon): add subdomain enumeration

Added SubdomainEnumerator class with multiple sources:
- crt.sh integration
- VirusTotal API support
- DNS brute force option

Closes #123
```

## Project Structure

```
drakben/
├── core/                  # Core functionality
│   ├── agent/            # Agent logic
│   ├── execution/        # Command execution
│   ├── intelligence/     # AI/LLM integration
│   ├── llm/              # LLM providers
│   ├── network/          # Network utilities
│   ├── security/         # Security features
│   ├── singularity/      # Code generation
│   ├── storage/          # Data persistence
│   ├── tools/            # Tool registry
│   └── ui/               # User interface
├── modules/              # Pentest modules
│   ├── native/           # Low-level modules
│   ├── research/         # Research tools
│   └── social_eng/       # Social engineering
├── llm/                  # LLM client
├── tests/                # Test suite
├── config/               # Configuration files
└── docs/                 # Documentation
```

## Adding New Tools

### Shell Tools

Register in `core/tools/tool_registry.py`:

```python
self.register(Tool(
    name="mytool",
    type=ToolType.SHELL,
    description="Description of my tool",
    phase=PentestPhase.RECON,
    command_template="mytool -t {target}",
    timeout=300,
))
```

### Python Tools

```python
# 1. Create the function
def _run_my_tool(self, target: str, **kwargs) -> dict:
    from modules.mymodule import my_function
    return my_function(target)

# 2. Register it
self.register(Tool(
    name="mytool",
    type=ToolType.PYTHON,
    description="Description",
    phase=PentestPhase.EXPLOIT,
    python_func=self._run_my_tool,
))
```

## Security Considerations

### Sensitive Data

- Never commit API keys or credentials
- Use environment variables for secrets
- Add test secrets to `.gitignore`

### Shell Commands

- Use `# nosec B602` for intentional shell usage
- Validate all user input with CommandSanitizer
- Document security implications

## Getting Help

- Open an issue for bugs
- Use discussions for questions
- Check existing issues before creating new ones

## License

By contributing, you agree that your contributions will be licensed under the project's MIT License.
