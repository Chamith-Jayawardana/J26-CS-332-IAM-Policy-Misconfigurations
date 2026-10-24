"""
IAM Policy Misconfiguration Dataset Builder (SO1 & SO2)
Author: C.L.D. Jayawardhana (IT23325296)
Research Component: IAM Policy Misconfiguration Detection

Constructs a scaled Role-Permission & Privilege Escalation dataset (600+ samples).
Captures overprivileged roles, risky trust policies, privilege escalation vectors, and secure least-privilege patterns.
Exports structured dataset to data/labelled_datasets/iam_consensus_dataset.json.
"""

import os
import json
import re
import random
from typing import List, Dict, Any

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def build_scaled_iam_dataset(output_path: str = None) -> Dict[str, Any]:
    """
    Constructs a 600+ sample IAM dataset covering all 4 classes:
      0: SECURE_IAM_POLICY
      1: IAM_OVERPRIVILEGED_ROLE
      2: IAM_INSECURE_TRUST_POLICY
      3: IAM_PRIVILEGE_ESCALATION
    """
    if output_path is None:
        output_path = os.path.join(PROJECT_ROOT, "data", "labelled_datasets", "iam_consensus_dataset.json")

    samples: List[Dict[str, Any]] = []

    # 1. Ingest real IAM blocks from iac_blocks.json
    blocks_path = os.path.join(PROJECT_ROOT, "data", "processed_blocks", "iac_blocks.json")
    if os.path.exists(blocks_path):
        with open(blocks_path, "r", encoding="utf-8") as f:
            blocks = json.load(f)

        for b in blocks:
            rt = b.get("resource_type", "")
            code = b.get("raw_code", "")
            repo = b.get("repo_name", "")
            name = b.get("resource_name", "")

            if any(k in rt.lower() for k in ["iam", "policy", "role"]):
                code_lower = code.lower()
                if "iam:passrole" in code_lower and ("ec2:runinstances" in code_lower or "lambda:createfunction" in code_lower):
                    label = 3 # Privilege Escalation
                elif "iam:attachuserpolicy" in code_lower or "iam:createpolicyversion" in code_lower or "iam:putuserpolicy" in code_lower:
                    label = 3 # Privilege Escalation
                elif 'principal = "*"' in code_lower or '"principal": "*"' in code_lower or '"aws": "*"' in code_lower:
                    label = 2 # Insecure Trust Policy
                elif '"action": "*"' in code_lower or 'action = ["*"]' in code_lower or ('"*" ' in code_lower and '"resource": "*"' in code_lower):
                    label = 1 # Overprivileged Role
                elif "admin" in name.lower() or "fullaccess" in code_lower:
                    label = 1
                elif "assumerole" in code_lower and "sts" in code_lower:
                    label = 2
                else:
                    label = 0 # Least privilege

                samples.append({
                    "id": f"raw_iam_{repo}_{name}_{len(samples)}",
                    "repo": repo,
                    "resource_type": rt,
                    "code": code,
                    "label": label
                })

    # 2. Systematic Synthesis of Complex IAM & Privilege Escalation Scenarios
    random.seed(42)

    # Class 1: Overprivileged Roles (~90 samples)
    services = ["s3", "ec2", "dynamodb", "rds", "lambda", "sqs", "sns"]
    for i in range(90):
        srv = services[i % len(services)]
        code = f'''resource "aws_iam_role_policy" "overprivileged_policy_{i}" {{
  name = "excessive-privileges-{srv}-{i}"
  role = "app-service-role-{i}"
  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Effect   = "Allow"
      Action   = ["{srv}:*", "iam:Get*", "iam:List*"]
      Resource = "*"
    }}]
  }})
}}'''
        samples.append({
            "id": f"syn_overpriv_{i}",
            "repo": "bishopfox_patterns",
            "resource_type": "aws_iam_role_policy",
            "code": code,
            "label": 1
        })

    # Class 2: Insecure Trust Relationships (~85 samples)
    for i in range(85):
        code = f'''resource "aws_iam_role" "insecure_trust_role_{i}" {{
  name = "unrestricted-assume-role-{i}"
  assume_role_policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Effect = "Allow"
      Principal = "*"
      Action = "sts:AssumeRole"
    }}]
  }})
}}'''
        samples.append({
            "id": f"syn_trust_{i}",
            "repo": "cloudgoat_scenarios",
            "resource_type": "aws_iam_role",
            "code": code,
            "label": 2
        })

    # Class 3: Privilege Escalation Vectors (~95 samples)
    # Covering BishopFox / RhinoSecurity Labs 14 known AWS IAM escalation methods
    esc_methods = [
        ('["iam:PassRole", "ec2:RunInstances"]', "*"),
        ('["iam:CreateAccessKey"]', "arn:aws:iam::123456789012:user/admin-*"),
        ('["iam:CreateLoginProfile"]', "arn:aws:iam::123456789012:user/*"),
        ('["iam:UpdateLoginProfile"]', "arn:aws:iam::123456789012:user/*"),
        ('["iam:AttachUserPolicy"]', "arn:aws:iam::123456789012:user/*"),
        ('["iam:AttachRolePolicy"]', "arn:aws:iam::123456789012:role/*"),
        ('["iam:PutUserPolicy"]', "*"),
        ('["iam:PutRolePolicy"]', "*"),
        ('["iam:AddUserToGroup"]', "arn:aws:iam::123456789012:group/Administrators"),
        ('["iam:SetDefaultPolicyVersion"]', "arn:aws:iam::123456789012:policy/*")
    ]

    for i in range(95):
        actions, resource = esc_methods[i % len(esc_methods)]
        code = f'''resource "aws_iam_policy" "escalation_policy_{i}" {{
  name        = "privilege-escalation-vector-{i}"
  description = "Allows unauthorized escalation of privileges"
  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Effect   = "Allow"
      Action   = {actions}
      Resource = "{resource}"
    }}]
  }})
}}'''
        samples.append({
            "id": f"syn_escalation_{i}",
            "repo": "iam_vulnerable_corpus",
            "resource_type": "aws_iam_policy",
            "code": code,
            "label": 3
        })

    # Class 0: Secure Least-Privilege IAM Policies (~100 samples)
    for i in range(100):
        s_id = f"bucket-records-{i}"
        code = f'''resource "aws_iam_policy" "least_privilege_policy_{i}" {{
  name        = "strict-least-privilege-{i}"
  description = "Compliant with CIS AWS Benchmark 1.4 Section 1"
  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "arn:aws:s3:::{s_id}/*"
    }}, {{
      Effect   = "Allow"
      Action   = ["kms:Decrypt"]
      Resource = "arn:aws:kms:us-east-1:123456789012:key/compliant-key-{i}"
    }}]
  }})
}}'''
        samples.append({
            "id": f"syn_secure_iam_{i}",
            "repo": "cis_benchmark_corpus",
            "resource_type": "aws_iam_policy",
            "code": code,
            "label": 0
        })

    # Shuffle and partition (80% Train, 20% Test)
    random.shuffle(samples)
    split_idx = int(0.8 * len(samples))
    train_samples = samples[:split_idx]
    test_samples = samples[split_idx:]

    dataset = {
        "metadata": {
            "total_samples": len(samples),
            "train_count": len(train_samples),
            "test_count": len(test_samples),
            "classes": {
                "0": "SECURE_IAM_POLICY",
                "1": "IAM_OVERPRIVILEGED_ROLE",
                "2": "IAM_INSECURE_TRUST_POLICY",
                "3": "IAM_PRIVILEGE_ESCALATION"
            },
            "class_distribution": {
                str(c): sum(1 for s in samples if s["label"] == c) for c in range(4)
            }
        },
        "train": train_samples,
        "test": test_samples
    }

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(dataset, f, indent=2)

    return dataset
