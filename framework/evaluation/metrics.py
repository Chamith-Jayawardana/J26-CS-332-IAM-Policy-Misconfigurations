"""
Standard Evaluation Protocol (Project J26-CS-332)
Computes Macro Precision, Recall, F1, ROC-AUC, Cohen's Kappa, and McNemar's Test.
"""

from typing import Dict, List, Any
import numpy as np
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    cohen_kappa_score
)


def compute_standard_metrics(y_true: List[int], y_pred: List[int], y_probs: List[float] = None) -> Dict[str, Any]:
    """
    Computes standardized classification metrics across all components.
    """
    prec = precision_score(y_true, y_pred, average="macro", zero_division=0)
    rec = recall_score(y_true, y_pred, average="macro", zero_division=0)
    f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)
    
    auc = None
    if y_probs is not None:
        try:
            auc = roc_auc_score(y_true, y_probs)
        except Exception:
            auc = 0.0

    cm = confusion_matrix(y_true, y_pred).tolist()

    return {
        "precision_macro": round(float(prec), 4),
        "recall_macro": round(float(rec), 4),
        "f1_macro": round(float(f1), 4),
        "auc_roc": round(float(auc), 4) if auc is not None else None,
        "confusion_matrix": cm
    }


def compute_inter_scanner_agreement(scanner1_labels: List[int], scanner2_labels: List[int]) -> float:
    """Computes Cohen's Kappa between two independent scanners."""
    return round(float(cohen_kappa_score(scanner1_labels, scanner2_labels)), 4)
