import pickle
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.datasets import make_classification
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from sklearn.model_selection import train_test_split

MODEL_DIR = Path(__file__).resolve().parents[3] / "ml" / "models"

MODEL_DIR.mkdir(parents=True, exist_ok=True)


def train_and_save_models() -> dict:
    X, y = make_classification(
        n_samples=400,
        n_features=20,
        n_informative=10,
        n_redundant=4,
        n_classes=2,
        random_state=42,
    )
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42)

    models = {
        "random_forest": RandomForestClassifier(n_estimators=100, random_state=42),
        "xgboost": XGBClassifier(n_estimators=60, max_depth=3, learning_rate=0.1, eval_metric="logloss", use_label_encoder=False),
        "lightgbm": LGBMClassifier(n_estimators=80, random_state=42),
        "logistic_regression": LogisticRegression(max_iter=2000),
    }

    results = {}
    for name, model in models.items():
        model.fit(X_train, y_train)
        pred = model.predict(X_test)
        results[name] = {
            "accuracy": round(float(accuracy_score(y_test, pred)), 4),
            "precision": round(float(precision_score(y_test, pred, zero_division=0)), 4),
            "recall": round(float(recall_score(y_test, pred, zero_division=0)), 4),
            "f1": round(float(f1_score(y_test, pred, zero_division=0)), 4),
            "roc_auc": round(float(roc_auc_score(y_test, pred)), 4),
        }
        with open(MODEL_DIR / f"{name}.pkl", "wb") as handle:
            pickle.dump(model, handle)

    best_model_name = max(results, key=lambda name: results[name]["f1"])
    return {"results": results, "best_model": best_model_name}
