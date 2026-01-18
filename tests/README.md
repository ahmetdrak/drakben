# DRAKBEN Test Suite

## Overview
Comprehensive test suite for DRAKBEN penetration testing framework.

## Requirements
```bash
pip install pytest pytest-cov pytest-asyncio pytest-mock
```

## Running Tests

### Run all tests:
```bash
pytest
```

### Run with coverage:
```bash
pytest --cov=core --cov=llm --cov=modules --cov-report=html
```

### Run specific test file:
```bash
pytest tests/test_executor.py
```

### Run with verbose output:
```bash
pytest -v
```

### Run specific test class:
```bash
pytest tests/test_zero_day_scanner.py::TestZeroDayScanner
```

### Run specific test method:
```bash
pytest tests/test_executor.py::TestExecutor::test_execute_simple_command
```

## Test Structure

```
tests/
├── conftest.py                    # Fixtures and configuration
├── test_executor.py               # Core executor tests
├── test_zero_day_scanner.py       # CVE scanner tests
├── test_payload_intelligence.py   # Payload generation tests
├── test_brain.py                  # LLM integration tests
└── README.md                      # This file
```

## Coverage Goals

Target: **80%+ code coverage**

Current modules tested:
- ✅ core.executor
- ✅ core.zero_day_scanner
- ✅ core.payload_intelligence
- ✅ llm.brain

## Writing New Tests

### Template:
```python
"""
Test suite for module_name
"""

import pytest
from module_name import ClassName


class TestClassName:
    """Test cases for ClassName"""
    
    def test_feature_name(self):
        """Test description"""
        # Arrange
        obj = ClassName()
        
        # Act
        result = obj.method()
        
        # Assert
        assert result is not None
```

## CI/CD Integration

Tests run automatically on:
- Every push to main branch
- Every pull request
- Daily scheduled runs

## Continuous Integration

GitHub Actions workflow runs:
1. Linting (flake8, black)
2. Type checking (mypy)
3. Unit tests (pytest)
4. Coverage report
5. Security scan

## Best Practices

1. **Arrange-Act-Assert** pattern
2. **Mock external dependencies** (API calls, file I/O)
3. **One assertion per test** (where possible)
4. **Descriptive test names**
5. **Test edge cases**

## Troubleshooting

### Import errors:
```bash
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

### Coverage not working:
```bash
pytest --cov=. --cov-report=term-missing
```

## Future Tests

- [ ] Integration tests
- [ ] E2E tests
- [ ] Performance tests
- [ ] Security tests
