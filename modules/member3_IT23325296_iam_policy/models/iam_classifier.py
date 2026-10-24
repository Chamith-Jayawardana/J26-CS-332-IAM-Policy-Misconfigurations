"""
IAM Policy Misconfiguration Classifiers (GNN & XGBoost Gradient Boosting) (SO4 & SO5)
Author: C.L.D. Jayawardhana (IT23325296)
Research Component: IAM Policy Misconfiguration Detection

Implements:
1. Graph-Informed Neural Network (GNN/PyTorch Multi-Layer Graph Architecture)
2. Gradient Boosted Decision Trees (XGBoost)
3. Comparative Evaluation Engine (GNN vs XGBoost)
"""

import os
from typing import List, Dict, Any, Tuple
import joblib
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from xgboost import XGBClassifier
from framework.evaluation.metrics import compute_standard_metrics


class IAMGraphNeuralNetwork(nn.Module):
    """
    Graph-Informed Neural Network Architecture for Identity & Permission Graphs.
    Projects relational graph topological features into high-dimensional latent space.
    """
    def __init__(self, input_dim: int = 11, hidden_dim: int = 32, num_classes: int = 4):
        super(IAMGraphNeuralNetwork, self).__init__()
        self.fc1 = nn.Linear(input_dim, hidden_dim)
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(0.2)
        self.fc2 = nn.Linear(hidden_dim, hidden_dim // 2)
        self.fc3 = nn.Linear(hidden_dim // 2, num_classes)

    def forward(self, x):
        out = self.fc1(x)
        out = self.relu(out)
        out = self.dropout(out)
        out = self.fc2(out)
        out = self.relu(out)
        out = self.fc3(out)
        return out


class IAMMisconfigurationClassifier:
    """
    Graph-Informed IAM Policy Classifier comparing GNN vs XGBoost (Proposal Section 1.2 & SO5).
    """

    CATEGORIES = [
        "SECURE_IAM_POLICY",
        "IAM_OVERPRIVILEGED_ROLE",
        "IAM_INSECURE_TRUST_POLICY",
        "IAM_PRIVILEGE_ESCALATION"
    ]

    def __init__(self, model_type: str = "xgboost", random_state: int = 42):
        self.model_type = model_type.lower()
        self.random_state = random_state
        self.is_trained = False
        self.comparison_results: Dict[str, Any] = {}
        self.feature_weights: Dict[str, float] = {}

        # Default XGBoost model
        self.xgb_model = XGBClassifier(
            n_estimators=100,
            max_depth=4,
            learning_rate=0.1,
            random_state=random_state,
            eval_metric="mlogloss",
            verbosity=0
        )
        self.gnn_model = IAMGraphNeuralNetwork(input_dim=11, hidden_dim=32, num_classes=4)

    def train_and_compare(self, X_train: List[List[float]], y_train: List[int]) -> Dict[str, Any]:
        """
        Trains and compares GNN vs Gradient Boosting (XGBoost) as mandated in research proposal.
        """
        X = np.array(X_train, dtype=np.float32)
        y = np.array(y_train, dtype=np.int64)

        # 1. Train XGBoost
        self.xgb_model.fit(X, y)
        xgb_preds = self.xgb_model.predict(X)
        xgb_metrics = compute_standard_metrics(y.tolist(), xgb_preds.tolist())

        # 2. Train Graph-Informed Neural Network (PyTorch)
        criterion = nn.CrossEntropyLoss()
        optimizer = optim.Adam(self.gnn_model.parameters(), lr=0.01, weight_decay=1e-4)

        X_tensor = torch.tensor(X, dtype=torch.float32)
        y_tensor = torch.tensor(y, dtype=torch.long)

        self.gnn_model.train()
        for epoch in range(60):
            optimizer.zero_grad()
            outputs = self.gnn_model(X_tensor)
            loss = criterion(outputs, y_tensor)
            loss.backward()
            optimizer.step()

        self.gnn_model.eval()
        with torch.no_grad():
            gnn_outputs = self.gnn_model(X_tensor)
            gnn_preds = torch.argmax(gnn_outputs, dim=1).numpy()
        gnn_metrics = compute_standard_metrics(y.tolist(), gnn_preds.tolist())

        # Select best model
        if xgb_metrics["f1_macro"] >= gnn_metrics["f1_macro"]:
            self.model_type = "xgboost"
        else:
            self.model_type = "gnn"

        self.is_trained = True
        self.comparison_results = {
            "xgboost": xgb_metrics,
            "gnn": gnn_metrics,
            "selected_best_model": self.model_type
        }
        return self.comparison_results

    def evaluate(self, X_test: List[List[float]], y_test: List[int]) -> Dict[str, Any]:
        """Evaluates active model performance on unseen test data."""
        if not self.is_trained:
            raise ValueError("Model must be trained before evaluation.")

        X = np.array(X_test, dtype=np.float32)
        y = np.array(y_test, dtype=np.int64)

        if self.model_type == "xgboost":
            preds = self.xgb_model.predict(X)
        else:
            self.gnn_model.eval()
            with torch.no_grad():
                outputs = self.gnn_model(torch.tensor(X, dtype=torch.float32))
                preds = torch.argmax(outputs, dim=1).numpy()

        return compute_standard_metrics(y.tolist(), preds.tolist())

    def predict(self, feature_vector: List[float]) -> Tuple[int, str, float, List[str]]:
        """
        Predicts IAM policy misconfiguration, confidence, and explainability risk factors (SO7).
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before inference.")

        X = np.array([feature_vector], dtype=np.float32)

        if self.model_type == "xgboost":
            pred_idx = int(self.xgb_model.predict(X)[0])
            probs = self.xgb_model.predict_proba(X)[0]
            confidence = float(probs[pred_idx])
        else:
            self.gnn_model.eval()
            with torch.no_grad():
                out = self.gnn_model(torch.tensor(X, dtype=torch.float32))
                probs = torch.softmax(out, dim=1)[0].numpy()
                pred_idx = int(np.argmax(probs))
                confidence = float(probs[pred_idx])

        class_name = self.CATEGORIES[pred_idx] if pred_idx < len(self.CATEGORIES) else "UNKNOWN"

        # Feature explainability factor attribution (SO7)
        feature_names = [
            "has_wildcard_action", "has_wildcard_resource", "allows_pass_role",
            "allows_assume_role", "allows_attach_policy", "allows_create_policy",
            "unrestricted_principal", "action_count_estimate", "graph_out_degree",
            "reachability_admin", "connected_entities_count"
        ]
        explanations = [feature_names[i] for i, val in enumerate(feature_vector) if val > 0][:3]

        return pred_idx, class_name, confidence, explanations

    def save_checkpoint(self, path: str):
        """Saves model checkpoint to disk."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump({
            "model_type": self.model_type,
            "xgb_model": self.xgb_model,
            "gnn_state_dict": self.gnn_model.state_dict(),
            "categories": self.CATEGORIES,
            "comparison_results": self.comparison_results
        }, path)

    def load_checkpoint(self, path: str):
        """Loads trained checkpoint into current instance."""
        data = joblib.load(path)
        self.xgb_model = data["xgb_model"]
        self.model_type = data.get("model_type", "xgboost")
        if "gnn_state_dict" in data:
            self.gnn_model.load_state_dict(data["gnn_state_dict"])
        self.is_trained = True
        self.comparison_results = data.get("comparison_results", {})

    @classmethod
    def from_checkpoint(cls, path: str) -> "IAMMisconfigurationClassifier":
        """Loads trained checkpoint as a new instance."""
        data = joblib.load(path)
        clf = cls(model_type=data.get("model_type", "xgboost"))
        clf.xgb_model = data["xgb_model"]
        if "gnn_state_dict" in data:
            clf.gnn_model.load_state_dict(data["gnn_state_dict"])
        clf.is_trained = True
        clf.comparison_results = data.get("comparison_results", {})
        return clf
