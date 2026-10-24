import os, sys
PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

print("="*65)
print(" RUNNING 50% DELIVERABLE: C.L.D. Jayawardhana (IT23325296)")
print("="*65)

from modules.member3_IT23325296_iam_policy.train import run_iam_training_pipeline
from modules.member3_IT23325296_iam_policy.infer import scan_iam_file

report = run_iam_training_pipeline()

print("\n--- Testing Live IAM Inference ---")
findings = scan_iam_file(os.path.join(PROJECT_ROOT, "data", "raw_repos", "terragoat_aws", "iam_policies.tf"),
                         os.path.join(PROJECT_ROOT, "results", "checkpoints", "iam_model.joblib"))
print(f"Findings Detected: {len(findings)}")
if findings:
    print(findings[0].to_json(indent=2))
