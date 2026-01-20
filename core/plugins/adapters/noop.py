# core/plugins/adapters/noop.py
# DRAKBEN NoOp Plugins - Placeholder implementations

from ..base import PluginBase, PluginSpec, PluginResult, PluginKind


class NoOpPlugin(PluginBase):
    """Base NoOp plugin - returns placeholder result"""
    
    async def execute(self, **kwargs) -> PluginResult:
        return PluginResult(
            success=True,
            output="No-op plugin executed successfully (placeholder)",
            data={"plugin_id": self.plugin_id, "noop": True}
        )


class NoOpRecon(NoOpPlugin):
    """Placeholder recon plugin"""
    pass


class NoOpAnalysis(NoOpPlugin):
    """Placeholder analysis plugin"""
    pass


class NoOpExploit(NoOpPlugin):
    """Placeholder exploit plugin"""
    pass


class NoOpPayload(NoOpPlugin):
    """Placeholder payload plugin"""
    pass


class NoOpBypass(NoOpPlugin):
    """Placeholder bypass plugin"""
    pass


class NoOpPost(NoOpPlugin):
    """Placeholder post-exploitation plugin"""
    pass


# Aliases for backward compatibility
NoopReconPlugin = NoOpRecon
NoopExploitPlugin = NoOpExploit
NoopPayloadPlugin = NoOpPayload
NoopAnalysisPlugin = NoOpAnalysis
