"""
Automated Verification Suite for Jayawardhana (IT23325296) 50% Milestone
Tests IAM graph construction, feature extraction, classifier training,
evaluation metrics, and live inference scanning.
"""

import os
import sys
import json

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from modules.member3_IT23325296_iam_policy.train import run_iam_training_pipeline
from modules.member3_IT23325296_iam_policy.infer import scan_iam_file


def verify_iam_deliverables():
    print(">>> STARTING 50% MILESTONE VERIFICATION SUITE: C.L.D. Jayawardhana (IT23325296) <<<\n")

    # 1. Run pipeline
    summary = run_iam_training_pipeline()
    assert summary is not None, "Pipeline execution returned None"

    # 2. Check files
    expected_files = [
        os.path.join(PROJECT_ROOT, "results", "checkpoints", "iam_model.joblib"),
        os.path.join(PROJECT_ROOT, "modules", "member3_IT23325296_iam_policy", "results", "evaluation_summary.json"),
        os.path.join(PROJECT_ROOT, "modules", "member3_IT23325296_iam_policy", "notebooks", "jayawardhana_iam_50_percent_demo.ipynb")
    ]

    for f in expected_files:
        assert os.path.exists(f), f"Expected deliverable not found: {f}"
        print(f"[VERIFIED FILE] -> {os.path.relpath(f, PROJECT_ROOT)} (Size: {os.path.getsize(f)} bytes)")

    # 3. Check metrics
    test_metrics = summary.get("test_metrics", summary.get("test_evaluation", {}))
    assert "f1_macro" in test_metrics, "F1-Score missing"
    assert "precision_macro" in test_metrics, "Precision missing"
    assert "recall_macro" in test_metrics, "Recall missing"
    print(f"\n[VERIFIED METRICS] Precision: {test_metrics['precision_macro']}, Recall: {test_metrics['recall_macro']}, Macro F1: {test_metrics['f1_macro']}")

    # 4. Verify inference
    checkpoint = os.path.join(PROJECT_ROOT, "results", "checkpoints", "iam_model.joblib")
    test_target = os.path.join(PROJECT_ROOT, "data", "raw_repos", "terragoat_aws", "iam_policies.tf")
    findings = scan_iam_file(test_target, checkpoint)
    assert len(findings) > 0, "Inference did not detect misconfigurations in iam_policies.tf"
    print(f"[VERIFIED INFERENCE] Scanner detected {len(findings)} misconfigurations in {os.path.basename(test_target)}")

    # 5. Check schema
    sample = findings[0]
    assert sample.member_id == "IT23325296", "Member ID mismatch"
    assert sample.is_advisory == True, "FR10 Advisory requirement violated"
    print(f"[VERIFIED SCHEMA] Finding matches unified schema v{sample.schema_version}")

    print("\n" + "=" * 65)
    print(" ALL 50% JAYAWARDHANA DELIVERABLES VERIFIED AND PASSED 100%!")
    print("=" * 65)


if __name__ == "__main__":
    verify_iam_deliverables()
