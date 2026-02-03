# core/visualizer.py
# Network Visualization Module for DRAKBEN

import logging
import os

from core.agent.state import get_state

# Configure logger
logger = logging.getLogger(__name__)

# Try to import PyVis and NetworkX gracefully
try:
    import networkx as nx
    from pyvis.network import Network

    DEPENDENCIES_AVAILABLE = True
except ImportError:
    logger.warning(
        "Visualization dependencies (pyvis, networkx) not found. Visualization disabled.",
    )
    DEPENDENCIES_AVAILABLE = False


class NetworkVisualizer:
    """Generates interactive network maps using PyVis.
    Equivalent to PentAGI's Knowledge Graph Graph.
    """

    def __init__(self, output_dir: str = "reports") -> None:
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def generate_map(self, filename: str = "network_map.html") -> str:
        """Generate network map from current AgentState.

        Returns:
            Absolute path to the generated HTML file.

        """
        if not DEPENDENCIES_AVAILABLE:
            logger.error("Cannot generate map: dependencies missing.")
            return ""

        state = get_state()

        # Create Graph
        graph = nx.Graph()

        # Add Target Node (Center)
        target_label = state.target or "Target System"
        graph.add_node(
            target_label, title="Target", color="#ff0000", shape="star", size=30,
        )

        # Add Service Nodes
        with state._lock:
            for port, svc in state.open_services.items():
                service_id = f"port_{port}"
                label = f"{port}/{svc.protocol}\n{svc.service}"
                if svc.version:
                    label += f"\n{svc.version}"

                # Determine color based on status
                color = "#00ff00"  # Green (Safe)
                if svc.vulnerable:
                    color = "#ff4444"  # Red (Vulnerable)
                elif svc.version:
                    color = "#ffff00"  # Yellow (Version Identified)

                graph.add_node(
                    service_id,
                    label=label,
                    title=str(svc),
                    color=color,
                    shape="box",
                )
                graph.add_edge(target_label, service_id)

                # Add Vulnerability Nodes attached to Service
                self._add_vulnerabilities(graph, service_id, port, state)

                # Add Credential Nodes attached to Service
                self._add_credentials(graph, service_id, svc.service, state)

        # Generate HTML
        try:
            net = Network(
                height="750px",
                width="100%",
                bgcolor="#222222",
                font_color="white",
            )
            net.from_nx(graph)

            # Physics settings for stability
            net.toggle_physics(True)

            output_path = os.path.join(self.output_dir, filename)
            abs_path = os.path.abspath(output_path)

            net.save_graph(abs_path)
            logger.info("Network map generated: %s", abs_path)
            return abs_path

        except Exception as e:
            logger.exception("Failed to generate network map: %s", e)
            return ""

    def _add_vulnerabilities(self, graph, parent_id, port, state) -> None:
        """Add vulnerability nodes."""
        for vuln in state.vulnerabilities:
            if vuln.port == port:
                vuln_id = f"vuln_{vuln.vuln_id}"
                graph.add_node(
                    vuln_id,
                    label=vuln.vuln_id,
                    title=f"Severity: {vuln.severity}",
                    color="#ff0000",
                    shape="diamond",
                )
                graph.add_edge(parent_id, vuln_id)

    def _add_credentials(self, graph, parent_id, service_name, state) -> None:
        """Add credential nodes."""
        for cred in state.credentials:
            if cred.service == service_name:
                cred_id = f"cred_{cred.username}"
                graph.add_node(
                    cred_id,
                    label=f"User: {cred.username}",
                    title="Credential",
                    color="#00ffff",  # Cyan
                    shape="icon",
                    icon={
                        "code": "\uf084",
                        "size": 50,
                        "color": "#00ffff",
                    },  # Key icon (if fontawesome supported) or fallback
                )
                graph.add_edge(parent_id, cred_id)


# Global Instance
_visualizer = None


def get_visualizer() -> NetworkVisualizer:
    global _visualizer
    if _visualizer is None:
        _visualizer = NetworkVisualizer()
    return _visualizer
