# Research Component 2: IAM Policy Misconfiguration Detection

- **Student Name:** C.L.D. Jayawardhana
- **Student ID:** IT23325296
- **Specialization:** Cyber Security (B.Sc. Hons in Information Technology)
- **Supervisors:** Mrs. Rangi Liyanage, Mrs. Helani Herath
- **Component Scope:** Detection of Over-Privilege, Risky Trust Policies, and Multi-Step Privilege Escalation paths in Cloud IAM using Graph Neural Networks (GCN, GraphSAGE, GAT) and Gradient Boosting (XGBoost).

---

## 📂 Folder Layout

```text
member3_IT23325296_iam_policy/
├── graph_builder/      # Role-Permission graph construction from IAM policies
├── models/             # GNN (PyTorch Geometric) and XGBoost models
├── notebooks/          # Google Colab / Jupyter demonstration notebooks
│   └── iam_gnn_training.ipynb
├── results/            # Performance metrics, Confusion matrices, ROC curves
├── train.py            # Model training & cross-validation
├── evaluate.py         # Baseline comparison (Checkov, Trivy, KICS, PMapper)
└── infer.py            # Standalone IAM risk inference & explainability CLI
```

---

## 🎯 Target Categories
1. Over-privileged roles and wildcard action abuse (`*`)
2. Insecure Trust Policy relationships (`sts:AssumeRole`)
3. Multi-step privilege escalation paths (`iam:PassRole`, `iam:AttachUserPolicy`)
