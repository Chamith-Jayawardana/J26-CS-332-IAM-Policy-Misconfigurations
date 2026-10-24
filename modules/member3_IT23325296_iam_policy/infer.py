"""
Standalone IAM Inference Scanner
Author: C.L.D. Jayawardhana (IT23325296)
Research Component: IAM Policy Misconfiguration Detection
"""

import os
import sys
import json
import argparse
from typing import List

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from framework.schemas.finding import SecurityFinding
from modules.member3_IT23325296_iam_policy.graph_builder.iam_features import IAMPolicyFeatureExtractor
from modules.member3_IT23325296_iam_policy.models.iam_classifier import IAMMisconfigurationClassifier


def scan_iam_file(file_path: str, checkpoint_path: str) -> List[SecurityFinding]:
    """Scans an IAM policy file and returns unified security findings."""
    if not os.path.exists(file_path):
        return []

    classifier = IAMMisconfigurationClassifier()
    classifier.load_checkpoint(checkpoint_path)
    extractor = IAMPolicyFeatureExtractor()

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    feat_vec = extractor.extract_features(content, role_id=os.path.basename(file_path))
    pred_idx, label_name, confidence, explanations = classifier.predict(feat_vec)

    findings = []
    if pred_idx != 0:  # Not secure
        finding = SecurityFinding(
            component_id="iam_detection",
            member_id="IT23325296",
            repository="iam-scan",
            file_path=file_path,
            line_range=[1, len(content.splitlines())],
            resource_id="aws_iam_policy.analyzed_policy",
            predicted_smell=label_name,
            confidence_score=round(confidence, 4),
            consensus_support=2,
            is_advisory=True,
            schema_version="v1.0",
            details=f"Policy classified as {label_name}. Top risk factors: {explanations}"
        )
        findings.append(finding)

    return findings


def main():
    parser = argparse.ArgumentParser(description="IAM Misconfiguration Scanner - C.L.D. Jayawardhana (IT23325296)")
    parser.add_argument("--file", "-f", type=str, default=os.path.join(PROJECT_ROOT, "data", "raw_repos", "terragoat_aws", "iam_policies.tf"))
    parser.add_argument("--checkpoint", "-c", type=str, default=os.path.join(PROJECT_ROOT, "results", "checkpoints", "iam_model.joblib"))

    args = parser.parse_args()
    findings = scan_iam_file(args.file, args.checkpoint)

    print(f"\n--- IAM Scan Complete: Found {len(findings)} Findings ---")
    for f in findings:
        print(f"[{f.predicted_smell}] Confidence: {f.confidence_score:.2f} | File: {os.path.basename(f.file_path)}")
        print(f"Details: {f.details}\n")


if __name__ == "__main__":
    main()
