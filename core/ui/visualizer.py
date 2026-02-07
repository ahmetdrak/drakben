# core/visualizer.py
# Network Visualization Module for DRAKBEN

import logging
import os

# Configure logger
logger = logging.getLogger(__name__)

# Try to import PyVis and NetworkX gracefully
try:
    import importlib.util

    DEPENDENCIES_AVAILABLE = (
        importlib.util.find_spec("pyvis") is not None
        and importlib.util.find_spec("networkx") is not None
    )
except Exception:
    DEPENDENCIES_AVAILABLE = False

if not DEPENDENCIES_AVAILABLE:
    logger.warning(
        "Visualization dependencies (pyvis, networkx) not found. Visualization disabled.",
    )


class NetworkVisualizer:
    """Generates interactive network maps using PyVis.
    Equivalent to PentAGI's Knowledge Graph Graph.
    """

    def __init__(self, output_dir: str = "reports") -> None:
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)


