# core/plugins/registry.py
# DRAKBEN Plugin Registry - Plugin yönetimi

import json
import importlib
from pathlib import Path
from typing import Dict, List, Optional, Type
from .base import PluginBase, PluginSpec, PluginKind, PluginResult


class PluginNotAvailable(Exception):
    """Plugin yüklenemedi hatası"""
    pass


class PluginRegistry:
    """
    Plugin kayıt ve yönetim sistemi
    config/plugins.json'dan plugin'leri yükler
    """
    
    def __init__(self):
        self._plugins: Dict[str, PluginBase] = {}
        self._specs: Dict[str, PluginSpec] = {}
        self._loaded = False
    
    def load_from_file(self, config_path: str = "config/plugins.json") -> int:
        """
        Plugin konfigürasyonunu dosyadan yükle
        
        Returns:
            Yüklenen plugin sayısı
        """
        config_file = Path(config_path)
        if not config_file.exists():
            return 0
        
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            plugins_data = data.get("plugins", [])
            loaded = 0
            
            for plugin_data in plugins_data:
                try:
                    spec = PluginSpec.from_dict(plugin_data)
                    self._specs[spec.plugin_id] = spec
                    
                    # Try to load actual plugin class
                    plugin = self._load_plugin_class(plugin_data, spec)
                    if plugin:
                        self._plugins[spec.plugin_id] = plugin
                        loaded += 1
                except Exception as e:
                    print(f"⚠️  Plugin yüklenemedi {plugin_data.get('plugin_id')}: {e}")
            
            self._loaded = True
            return loaded
            
        except Exception as e:
            print(f"❌ Plugin config yüklenemedi: {e}")
            return 0
    
    def _load_plugin_class(self, plugin_data: Dict, spec: PluginSpec) -> Optional[PluginBase]:
        """Load plugin class from module"""
        module_path = plugin_data.get("module")
        class_name = plugin_data.get("class_name")
        
        if not module_path or not class_name:
            return None
        
        try:
            module = importlib.import_module(module_path)
            plugin_class = getattr(module, class_name)
            return plugin_class(spec)
        except (ImportError, AttributeError) as e:
            # Module not found, return placeholder
            return None
    
    def register(self, plugin: PluginBase):
        """Manuel plugin kaydı"""
        self._plugins[plugin.plugin_id] = plugin
        self._specs[plugin.plugin_id] = plugin.spec
    
    def get(self, plugin_id: str) -> Optional[PluginBase]:
        """Plugin al"""
        return self._plugins.get(plugin_id)
    
    def get_by_kind(self, kind: PluginKind) -> List[PluginBase]:
        """Kategoriye göre plugin'leri al"""
        return [p for p in self._plugins.values() if p.kind == kind]
    
    def get_all_specs(self) -> List[PluginSpec]:
        """Tüm plugin spec'lerini al"""
        return list(self._specs.values())
    
    def list_plugins(self) -> List[Dict]:
        """Plugin listesini al"""
        result = []
        for plugin_id, spec in self._specs.items():
            result.append({
                "id": plugin_id,
                "name": spec.name,
                "kind": spec.kind.value,
                "version": spec.version,
                "description": spec.description,
                "available": plugin_id in self._plugins,
                "requires_approval": spec.requires_approval
            })
        return result
    
    async def execute_plugin(self, plugin_id: str, **kwargs) -> PluginResult:
        """Plugin çalıştır"""
        plugin = self.get(plugin_id)
        
        if not plugin:
            return PluginResult(
                success=False,
                errors=[f"Plugin not available: {plugin_id}"]
            )
        
        # Initialize if needed
        if not plugin.initialized:
            await plugin.initialize()
        
        # Validate args
        validation_errors = plugin.validate_args(**kwargs)
        if validation_errors:
            return PluginResult(
                success=False,
                errors=validation_errors
            )
        
        # Execute
        try:
            result = await plugin.execute(**kwargs)
            return result
        except Exception as e:
            return PluginResult(
                success=False,
                errors=[f"Plugin execution error: {str(e)}"]
            )
        finally:
            await plugin.cleanup()


# Global registry instance
_registry: Optional[PluginRegistry] = None


def get_registry() -> PluginRegistry:
    """Get global plugin registry"""
    global _registry
    if _registry is None:
        _registry = PluginRegistry()
        _registry.load_from_file()
    return _registry
