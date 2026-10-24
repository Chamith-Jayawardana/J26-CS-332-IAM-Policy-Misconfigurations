"""
Unified Cloud and IaC Security Smell Taxonomy (Project J26-CS-332)
Maps rules from Checkov, Trivy, and KICS to standardized security smell categories.
"""

from typing import Dict, Optional

# Core Security Categories across the 4 domains
TAXONOMY_CATEGORIES = {
    # 1. IaC & Template Level (Samarakoon - IT23409378)
    "IAC_UNRESTRICTED_INGRESS": "Unrestricted ingress/security group access in template",
    "IAC_HARDCODED_SECRET": "Hardcoded credentials or API keys in template",
    "IAC_MISSING_ENCRYPTION": "Resource declared without encryption at rest/transit",
    "IAC_OVERPRIVILEGED_POLICY": "Wildcard permissions or unrestricted resource scope in template",
    "IAC_PUBLIC_STORAGE": "Storage resource declared with public read/write permission",
    "IAC_INSECURE_COMMUNICATION": "Plaintext protocol configured instead of TLS/HTTPS",
    "IAC_MISSING_LOGGING": "Audit logging or access monitoring disabled",
    
    # 2. Cloud Storage Domain (Shamrihan - IT23293458)
    "STORAGE_EXPOSED_BUCKET": "Publicly accessible object storage bucket",
    "STORAGE_WEAK_ENCRYPTION": "Missing KMS / default unencrypted storage bucket",
    "STORAGE_INSECURE_ACL": "Overly permissive Access Control Lists (ACLs)",
    "STORAGE_PUBLIC_ACCESS": "Disabled Block Public Access settings",
    
    # 3. IAM Domain (Jayawardhana - IT23325296)
    "IAM_OVERPRIVILEGED_ROLE": "Role assigned administrative or wildcard actions",
    "IAM_INSECURE_TRUST_POLICY": "Trust policy allows untrusted external principals",
    "IAM_PRIVILEGE_ESCALATION": "Permission chain allowing privilege escalation",
    
    # 4. Network Security Group Domain (Michael - IT23233430)
    "NSG_UNRESTRICTED_SSH": "SSH Port 22 open to 0.0.0.0/0",
    "NSG_UNRESTRICTED_RDP": "RDP Port 3389 open to 0.0.0.0/0",
    "NSG_OPEN_DATABASE_PORT": "Database port exposed to the internet",
    "NSG_ANOMALOUS_RULE": "Anomalous or excessively wide port range rule"
}

# Cross-Scanner Rule Mapping Table (Checkov, Trivy, KICS -> Unified Taxonomy)
SCANNER_RULE_MAP: Dict[str, Dict[str, str]] = {
    "checkov": {
        "CKV_AWS_20": "IAC_PUBLIC_STORAGE",
        "CKV_AWS_19": "IAC_MISSING_ENCRYPTION",
        "CKV_AWS_24": "IAC_UNRESTRICTED_INGRESS",
        "CKV_AWS_25": "IAC_UNRESTRICTED_INGRESS",
        "CKV_AWS_60": "IAC_OVERPRIVILEGED_POLICY",
        "CKV_AWS_61": "IAC_OVERPRIVILEGED_POLICY",
        "CKV_AWS_41": "IAC_HARDCODED_SECRET",
        "CKV_AWS_18": "IAC_MISSING_LOGGING",
    },
    "trivy": {
        "AVD-AWS-0086": "IAC_PUBLIC_STORAGE",
        "AVD-AWS-0088": "IAC_MISSING_ENCRYPTION",
        "AVD-AWS-0107": "IAC_UNRESTRICTED_INGRESS",
        "AVD-AWS-0057": "IAC_OVERPRIVILEGED_POLICY",
        "AVD-AWS-0089": "IAC_MISSING_LOGGING",
    },
    "kics": {
        "b05dd33c-747d-4c30-a92a-3e89e9c102a6": "IAC_PUBLIC_STORAGE",
        "084c6686-2a70-4710-91b1-000393e54c12": "IAC_MISSING_ENCRYPTION",
        "e0b04a99-0b13-4cf2-807d-5a98bf6f80d5": "IAC_UNRESTRICTED_INGRESS",
        "8f407764-583e-4af8-af31-295b9554bf3d": "IAC_OVERPRIVILEGED_POLICY",
    }
}

def map_rule_to_smell(scanner_name: str, rule_id: str) -> Optional[str]:
    """Resolves vendor-specific rule ID into the common security smell category."""
    scanner_dict = SCANNER_RULE_MAP.get(scanner_name.lower(), {})
    return scanner_dict.get(rule_id, None)
