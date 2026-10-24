# 50% Mid-Term Deliverable: IAM Policy Misconfiguration Detection
**Student Name:** C.L.D. Jayawardhana  
**Student ID:** IT23325296  
**Project:** J26-CS-332 - Intelligent Cloud Misconfiguration Detection Framework  
**Specialization:** Cyber Security (SLIIT)  

---
## 📦 What is inside this package:
1. `modules/member3_IT23325296_iam_policy/`
   - `graph_builder/iam_graph.py`: Directed NetworkX graph of IAM Roles, Actions, and Targets
   - `graph_builder/iam_features.py`: Extracts 11 topological & privilege escalation features
   - `models/iam_classifier.py`: Graph-Informed Classifier for Overprivileged/Escalation policies
   - `train.py`: Training orchestrator & evaluation suite
   - `infer.py`: Standalone IAM inference scanner
   - `notebooks/jayawardhana_iam_50_percent_demo.ipynb`: Interactive Jupyter Notebook for presentation
   - `results/evaluation_summary.json`: Detailed evaluation metrics
2. `framework/`: Group's unified finding schema
3. `data/raw_repos/terragoat_aws/`: Vulnerable IAM policies & roles
4. `results/checkpoints/iam_model.joblib`: Pre-trained IAM model checkpoint
5. `run_demo.py` & `verify_iam_50.py`: Automated execution & verification test suites

---
## 🚀 One-Click Setup (Windows):
Double click **`setup_env.bat`** (or open Command Prompt / PowerShell in this folder and run):
```bash
pip install -r requirements.txt
```

---
## 🎬 How to Run & Present:
### Option A (Recommended for Viva/Defense - Jupyter Notebook):
Double click **`launch_notebook.bat`** or run:
```bash
jupyter notebook modules/member3_IT23325296_iam_policy/notebooks/jayawardhana_iam_50_percent_demo.ipynb
```

### Option B (Terminal Demo):
Double click **`run_demo.bat`** or run:
```bash
python run_demo.py
```

### Option C (Run All Automated Tests):
Double click **`verify_tests.bat`** or run:
```bash
python verify_iam_50.py
```
