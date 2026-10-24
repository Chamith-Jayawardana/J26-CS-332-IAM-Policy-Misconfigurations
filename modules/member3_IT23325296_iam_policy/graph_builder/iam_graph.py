"""
IAM Role-Permission & Identity Graph Builder (SO2)
Author: C.L.D. Jayawardhana (IT23325296)
Research Component: IAM Policy Misconfiguration Detection

Models cloud identities, roles, managed/inline policies, actions, and trust relationships
as a directed graph to discover privilege escalation paths and structural risk.
"""

from typing import List, Dict, Any, Set, Tuple


class IAMRolePermissionGraph:
    """
    Constructs a directed graph representing IAM identities, permissions, and trust paths.
    Nodes: Users, Roles, Policies, Actions, Resources
    Edges: ASSUMES_ROLE, ATTACHES_POLICY, ALLOWS_ACTION, TARGETS_RESOURCE
    """

    def __init__(self):
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Tuple[str, str, str]] = []  # (source, target, relation_type)
        self.adjacency: Dict[str, List[str]] = {}

    def add_node(self, node_id: str, node_type: str, properties: Dict[str, Any] = None):
        """Adds a node to the graph."""
        self.nodes[node_id] = {
            "type": node_type,
            "properties": properties or {}
        }
        if node_id not in self.adjacency:
            self.adjacency[node_id] = []

    def add_edge(self, source_id: str, target_id: str, relation: str):
        """Adds a directed edge between two IAM entities."""
        if source_id not in self.nodes:
            self.add_node(source_id, "unknown")
        if target_id not in self.nodes:
            self.add_node(target_id, "unknown")

        self.edges.append((source_id, target_id, relation))
        self.adjacency[source_id].append(target_id)

    def calculate_graph_metrics(self, entity_id: str) -> Dict[str, float]:
        """Calculates relational security metrics for a given identity or role."""
        out_degree = len(self.adjacency.get(entity_id, []))
        
        # Check if can reach an administrative policy or wildcard action
        can_reach_admin = 0.0
        visited = set()
        queue = [entity_id]
        
        while queue:
            curr = queue.pop(0)
            if curr in visited:
                continue
            visited.add(curr)
            
            # Check node for admin or wildcard
            if "admin" in curr.lower() or "*" in curr:
                can_reach_admin = 1.0
                break
                
            for neighbor in self.adjacency.get(curr, []):
                if neighbor not in visited:
                    queue.append(neighbor)

        return {
            "out_degree": float(out_degree),
            "reachability_admin": can_reach_admin,
            "connected_entities_count": float(len(visited) - 1)
        }
