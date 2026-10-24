"""
IAM Policy Risk Feature Extractor (SO3)
Author: C.L.D. Jayawardhana (IT23325296)
Research Component: IAM Policy Misconfiguration Detection

Extracts policy semantics, permission breadth, trust policy exposure, and privilege escalation metrics.
"""

import re
from typing import Dict, Any, List
from modules.member3_IT23325296_iam_policy.graph_builder.iam_graph import IAMRolePermissionGraph


class IAMPolicyFeatureExtractor:
    """
    Extracts numerical risk vectors combining policy text semantics and graph topology.
    """

    FEATURE_NAMES = [
        "has_wildcard_action",       # 1 if Action contains *
        "has_wildcard_resource",     # 1 if Resource contains *
        "allows_pass_role",          # 1 if iam:PassRole is allowed (escalation vector)
        "allows_assume_role",        # 1 if sts:AssumeRole is allowed
        "allows_attach_policy",      # 1 if iam:Attach* is allowed
        "allows_create_policy",      # 1 if iam:CreatePolicyVersion is allowed
        "unrestricted_principal",    # 1 if Principal: * in trust policy
        "action_count_estimate",     # Estimated number of actions granted
        "graph_out_degree",          # Graph out degree
        "reachability_admin",        # 1 if can reach administrative node in graph
        "connected_entities_count"   # Number of reachable entities in IAM graph
    ]

    def extract_features(self, policy_text: str, role_id: str = "role-001") -> List[float]:
        """Extracts ordered numerical feature vector for an IAM statement."""
        text_lower = policy_text.lower()

        # Wildcard analysis
        has_wildcard_action = 1.0 if re.search(r'["\']action["\']\s*:\s*(?:["\']\*["\']|\[.*?["\']\*["\'].*?\])', text_lower) or 'action = ["*"]' in text_lower or 'action = "*"' in text_lower else 0.0
        has_wildcard_resource = 1.0 if re.search(r'["\']resource["\']\s*:\s*["\']\*["\']', text_lower) or 'resource = "*"' in text_lower else 0.0

        # Privilege escalation vectors
        allows_pass_role = 1.0 if "iam:passrole" in text_lower else 0.0
        allows_assume_role = 1.0 if "sts:assumerole" in text_lower else 0.0
        allows_attach_policy = 1.0 if "iam:attachuserpolicy" in text_lower or "iam:attachrolepolicy" in text_lower else 0.0
        allows_create_policy = 1.0 if "iam:createpolicyversion" in text_lower else 0.0

        # Trust policy exposure
        unrestricted_principal = 1.0 if re.search(r'["\']principal["\']\s*:\s*["\']\*["\']', text_lower) else 0.0

        action_count = float(len(re.findall(r'["\'][a-z0-9_-]+:[a-z0-9_*]+["\']', text_lower)))
        if has_wildcard_action:
            action_count = max(action_count, 100.0)

        # Build local graph representation
        graph = IAMRolePermissionGraph()
        graph.add_node(role_id, "IAMRole")
        if allows_assume_role:
            graph.add_node("sts:AssumeRole", "Action")
            graph.add_edge(role_id, "sts:AssumeRole", "EXECUTES")
        if allows_pass_role:
            graph.add_node("iam:PassRole", "Action")
            graph.add_edge(role_id, "iam:PassRole", "EXECUTES")
        if has_wildcard_action:
            graph.add_node("AdministratorAccess", "AdminPolicy")
            graph.add_edge(role_id, "AdministratorAccess", "ATTACHES")

        graph_metrics = graph.calculate_graph_metrics(role_id)

        vector = [
            has_wildcard_action,
            has_wildcard_resource,
            allows_pass_role,
            allows_assume_role,
            allows_attach_policy,
            allows_create_policy,
            unrestricted_principal,
            action_count,
            graph_metrics["out_degree"],
            graph_metrics["reachability_admin"],
            graph_metrics["connected_entities_count"]
        ]
        return vector
