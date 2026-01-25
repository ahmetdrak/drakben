# Docker Sandbox Implementation Plan

## Overview
Docker sandbox entegrasyonu ile kod yürütmelerini izole edilmiş container'larda çalıştırma.

## Mimari Tasarım

### 1. Sandbox Manager
```python
# core/sandbox_manager.py
class DockerSandboxManager:
    """Manages Docker containers for code execution"""
    
    def create_sandbox(self, image: str = "python:3.11-slim") -> str:
        """Create isolated container, return container_id"""
        
    def execute_in_sandbox(self, container_id: str, code: str) -> Dict:
        """Execute code in sandbox, return result"""
        
    def cleanup(self, container_id: str):
        """Remove container after execution"""
```

### 2. Execution Engine Integration
- `SmartTerminal.execute()` metoduna sandbox seçeneği ekle
- Güvenlik seviyesine göre otomatik sandbox kullanımı
- Fallback: Sandbox yoksa normal execution

### 3. Security Levels
- **Level 1**: Normal execution (mevcut)
- **Level 2**: Sandbox for unknown code
- **Level 3**: Sandbox for all code (strict mode)

## Implementation Steps

1. **Docker Client Setup**
   - `docker` Python client library
   - Container lifecycle management
   - Resource limits (CPU, memory)

2. **Code Execution**
   - Copy code to container
   - Execute with timeout
   - Capture output
   - Cleanup

3. **Configuration**
   - Enable/disable sandbox mode
   - Docker image selection
   - Resource limits

## Benefits
- ✅ Isolated execution environment
- ✅ Prevents system modification
- ✅ Easy cleanup
- ✅ Resource control

## Trade-offs
- ⚠️ Docker dependency
- ⚠️ Performance overhead
- ⚠️ Setup complexity

## Status
**PLANNED** - Ready for implementation when needed.
