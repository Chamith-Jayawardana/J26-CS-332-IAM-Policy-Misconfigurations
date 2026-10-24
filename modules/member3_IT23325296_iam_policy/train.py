"""
IAM Policy Model Training & Comparative Evaluation Pipeline (SO4, SO5, SO6)
Author: C.L.D. Jayawardhana (IT23325296)
Research Component: IAM Policy Misconfiguration Detection

Builds a scaled Role-Permission & Privilege Escalation dataset (750 samples),
constructs Role-Permission Graphs, extracts 11 topological risk vectors,
trains and benchmarks Graph Neural Network (GNN) vs Gradient Boosting (XGBoost),
and saves checkpoints and comparative evaluation summary reports.
"""

import os
import sys
import json
from typing import List, Dict, Any, Tuple
import numpy as np

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from modules.member3_IT23325296_iam_policy.dataset_builder import build_scaled_iam_dataset
from modules.member3_IT23325296_iam_policy.graph_builder.iam_features import IAMPolicyFeatureExtractor
from modules.member3_IT23325296_iam_policy.models.iam_classifier import IAMMisconfigurationClassifier


def run_iam_training_pipeline():
    print("=" * 70)
    print(" PROJECT J26-CS-332: IAM Policy Misconfiguration Detection")
    print(" Author: C.L.D. Jayawardhana (IT23325296)")
    print(" Milestone: 50% Review (Models: PyTorch GNN vs Gradient Boosting)")
    print("=" * 70)

    dataset_path = os.path.join(PROJECT_ROOT, "data", "labelled_datasets", "iam_consensus_dataset.json")
    checkpoint_path = os.path.join(PROJECT_ROOT, "results", "checkpoints", "iam_model.joblib")
    results_dir = os.path.join(PROJECT_ROOT, "modules", "member3_IT23325296_iam_policy", "results")
    reports_dir = os.path.join(PROJECT_ROOT, "results", "reports")
    os.makedirs(results_dir, exist_ok=True)
    os.makedirs(reports_dir, exist_ok=True)

    # 1. Dataset Construction (SO1 & SO2)
    print("\n[Step 1/4] Constructing Scaled IAM & Privilege Escalation Dataset (750 samples)...")
    dataset = build_scaled_iam_dataset(dataset_path)
    total_samples = dataset["metadata"]["total_samples"]
    train_samples = dataset["train"]
    test_samples = dataset["test"]

    print(f"  -> Total IAM Policies / Roles Generated: {total_samples}")
    print(f"  -> Train Split: {len(train_samples)} samples | Test Split: {len(test_samples)} samples")
    print(f"  -> Class Distribution: {dataset['metadata']['class_distribution']}")

    # 2. Graph Construction & Feature Extraction (SO3)
    print("\n[Step 2/4] Constructing Role-Permission Graphs & Extracting Topological Risk Vectors...")
    extractor = IAMPolicyFeatureExtractor()

    X_train = [extractor.extract_features(s["code"], role_id=s["id"]) for s in train_samples]
    y_train = [s["label"] for s in train_samples]

    X_test = [extractor.extract_features(s["code"], role_id=s["id"]) for s in test_samples]
    y_test = [s["label"] for s in test_samples]

    print(f"  -> Extracted 11 graph-informed risk features for {len(X_train)} train and {len(X_test)} test instances.")

    # 3. Model Training & Comparison (GNN vs XGBoost) (SO4 & SO5)
    print("\n[Step 3/4] Training & Comparing Proposed Models (GNN PyTorch vs XGBoost)...")
    classifier = IAMMisconfigurationClassifier(random_state=42)
    comparison = classifier.train_and_compare(X_train, y_train)

    print("\n  --- Comparative Model Performance (SO5) ---")
    print(f"  * [XGBoost]     Macro F1: {comparison['xgboost']['f1_macro']:.4f} | Precision: {comparison['xgboost']['precision_macro']:.4f} | Recall: {comparison['xgboost']['recall_macro']:.4f}")
    print(f"  * [GNN PyTorch] Macro F1: {comparison['gnn']['f1_macro']:.4f} | Precision: {comparison['gnn']['precision_macro']:.4f} | Recall: {comparison['gnn']['recall_macro']:.4f}")
    print(f"  => Winning Architecture Selected for Deployment: {comparison['selected_best_model'].upper()}")

    # 4. Evaluation on Held-out Test Set (SO6)
    print("\n[Step 4/4] Evaluating Winning Model on Held-out Test Partition (150 samples)...")
    test_metrics = classifier.evaluate(X_test, y_test)
    print(f"  -> Test Macro Precision: {test_metrics['precision_macro']:.4f}")
    print(f"  -> Test Macro Recall:    {test_metrics['recall_macro']:.4f}")
    print(f"  -> Test Macro F1-Score:  {test_metrics['f1_macro']:.4f}")
    print(f"  -> Confusion Matrix:     {test_metrics['confusion_matrix']}")

    # Save Checkpoint
    classifier.save_checkpoint(checkpoint_path)
    print(f"\n[Checkpoint Saved] -> {checkpoint_path}")

    # Save Summary Report
    summary = {
        "author": "C.L.D. Jayawardhana (IT23325296)",
        "component": "IAM Policy Misconfiguration Detection",
        "milestone": "50% Mid-Term Progress Review",
        "models_evaluated": ["GNN (PyTorch)", "XGBoost Gradient Boosting"],
        "selected_best_model": comparison["selected_best_model"],
        "dataset_statistics": {
            "total_samples": total_samples,
            "train_count": len(train_samples),
            "test_count": len(test_samples),
            "class_distribution": dataset["metadata"]["class_distribution"]
        },
        "feature_count": len(IAMPolicyFeatureExtractor.FEATURE_NAMES),
        "comparative_model_results": {
            "xgboost": comparison["xgboost"],
            "gnn": comparison["gnn"]
        },
        "test_metrics": test_metrics
    }

    summary_file = os.path.join(results_dir, "evaluation_summary.json")
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    with open(os.path.join(reports_dir, "iam_evaluation_report.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"[Summary Report Exported] -> {summary_file}")
    print("\n[SUCCESS] Member 3 (IAM) 50% Pipeline Complete & Proposals 100% Aligned!")
    return summary


if __name__ == "__main__":
    run_iam_training_pipeline()
