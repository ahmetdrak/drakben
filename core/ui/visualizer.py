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
        importlib.util.find_spec("pyvis") is not None and importlib.util.find_spec("networkx") is not None
    )
except Exception:
    DEPENDENCIES_AVAILABLE = False

if not DEPENDENCIES_AVAILABLE:
    logger.warning(
        "Visualization dependencies (pyvis, networkx) not found. Visualization disabled.",
    )


class NetworkVisualizer:
    """Generates interactive network maps using PyVis.

    Stub: Requires pyvis and networkx (pip install -r requirements-extra.txt).
    """

    def __init__(self, output_dir: str = "reports") -> None:
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def generate_map(self, nodes: list, edges: list, filename: str = "network_map.html") -> str:
        """Generate interactive network map.

        Args:
            nodes: List of network nodes to visualize.
            edges: List of connections between nodes.
            filename: Output HTML filename.

        Returns:
            Path to the generated HTML file.

        """
        if not DEPENDENCIES_AVAILABLE:
            msg = "NetworkVisualizer requires pyvis and networkx. Install: pip install -r requirements-extra.txt"
            raise NotImplementedError(msg)

        from pyvis.network import Network

        net = Network(height="750px", width="100%", directed=True)
        for node in nodes:
            label = node.get("label", str(node)) if isinstance(node, dict) else str(node)
            net.add_node(label, label=label)
        for edge in edges:
            if isinstance(edge, dict):
                net.add_edge(edge.get("from", ""), edge.get("to", ""))
            elif isinstance(edge, (list, tuple)) and len(edge) >= 2:
                net.add_edge(str(edge[0]), str(edge[1]))
        output_path = os.path.join(self.output_dir, filename)
        net.save_graph(output_path)
        logger.info("Network map saved to %s", output_path)
        return output_path
