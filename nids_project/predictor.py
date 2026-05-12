"""
Predictor Module
Loads trained models and runs inference on new network traffic samples.
Authors: Muhammad Tayyab (BSSE23018), Tehreem Mazhar (BSSE23086)
"""

import numpy as np
import pandas as pd
import pickle
import json
import os


# Default values for features not provided in a manual prediction request
FEATURE_DEFAULTS = {
    "duration": 0, "protocol_type": "tcp", "service": "http", "flag": "SF",
    "src_bytes": 0, "dst_bytes": 0, "land": 0, "wrong_fragment": 0, "urgent": 0,
    "hot": 0, "num_failed_logins": 0, "logged_in": 0, "num_compromised": 0,
    "root_shell": 0, "su_attempted": 0, "num_root": 0, "num_file_creations": 0,
    "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0,
    "is_host_login": 0, "is_guest_login": 0, "count": 1, "srv_count": 1,
    "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0,
    "srv_rerror_rate": 0.0, "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
    "srv_diff_host_rate": 0.0, "dst_host_count": 1, "dst_host_srv_count": 1,
    "dst_host_same_srv_rate": 1.0, "dst_host_diff_srv_rate": 0.0,
    "dst_host_same_src_port_rate": 0.0, "dst_host_srv_diff_host_rate": 0.0,
    "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0,
    "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0
}

# NSL-KDD column names (without label/difficulty)
NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
]


class Predictor:
    """
    Loads pre-trained models from disk and performs predictions.
    PRIMARY MODEL: Random Forest (best F1-score, explainable, robust).
    SECONDARY: Isolation Forest used for unsupervised anomaly context.
    """

    def __init__(self, model_dir="models/"):
        self.model_dir = model_dir
        self._load_artifacts()

    def _load_artifacts(self):
        """Load all model files, scaler, and encoders from disk."""
        def load(name):
            path = os.path.join(self.model_dir, name)
            with open(path, "rb") as f:
                return pickle.load(f)

        self.rf_model = load("random_forest.pkl")          # Primary model
        self.svm_model = load("svm.pkl")                   # Secondary supervised
        self.lr_model = load("logistic_regression.pkl")    # Baseline supervised
        self.iso_model = load("isolation_forest.pkl")      # Unsupervised anomaly
        self.km_model = load("kmeans.pkl")                 # Unsupervised clustering
        self.scaler = load("scaler.pkl")                   # StandardScaler
        self.label_encoders = load("label_encoders.pkl")   # Categorical encoders

        # Load expected feature column order
        with open(os.path.join(self.model_dir, "feature_cols.json"), "r") as f:
            self.feature_cols = json.load(f)

        print("[INFO] All artifacts loaded.")

    def _build_feature_vector(self, features: dict) -> np.ndarray:
        """
        Convert a dict of features into a scaled numpy array.
        Missing features are filled with defaults.
        Categorical features are label-encoded using saved encoders.
        """
        # Fill missing features with defaults
        sample = {**FEATURE_DEFAULTS, **features}

        # Encode categorical features using saved LabelEncoders
        categorical_cols = ["protocol_type", "service", "flag"]
        for col in categorical_cols:
            le = self.label_encoders.get(col)
            val = str(sample.get(col, "tcp"))
            if le is not None:
                # Handle unseen labels gracefully
                if val in le.classes_:
                    sample[col] = int(le.transform([val])[0])
                else:
                    sample[col] = 0  # Fallback to first class

        # Build ordered feature array matching training column order
        vector = np.array([float(sample.get(col, 0)) for col in self.feature_cols])
        vector_scaled = self.scaler.transform(vector.reshape(1, -1))
        return vector_scaled

    def predict(self, features: dict) -> dict:
        """
        Run prediction using ALL models and return a comprehensive result.
        Primary decision comes from Random Forest.

        Returns:
            dict with label, confidence, and all model predictions.
        """
        X = self._build_feature_vector(features)

        # --- Primary: Random Forest ---
        rf_pred = int(self.rf_model.predict(X)[0])
        rf_prob = float(self.rf_model.predict_proba(X)[0][rf_pred])

        # --- Secondary supervised ---
        svm_pred = int(self.svm_model.predict(X)[0])
        lr_pred = int(self.lr_model.predict(X)[0])

        # --- Unsupervised anomaly ---
        iso_raw = int(self.iso_model.predict(X)[0])
        iso_pred = 1 if iso_raw == -1 else 0  # -1=anomaly→attack

        return {
            "primary_model": "Random Forest",
            "label": "ATTACK" if rf_pred == 1 else "NORMAL",
            "binary": rf_pred,
            "confidence": round(rf_prob * 100, 2),
            "all_models": {
                "Random Forest": "ATTACK" if rf_pred == 1 else "NORMAL",
                "SVM": "ATTACK" if svm_pred == 1 else "NORMAL",
                "Logistic Regression": "ATTACK" if lr_pred == 1 else "NORMAL",
                "Isolation Forest": "ATTACK" if iso_pred == 1 else "NORMAL",
            }
        }

    def predict_batch(self, df: pd.DataFrame) -> list:
        """
        Batch prediction over a CSV DataFrame.
        Handles files with or without column headers.
        """
        results = []
        # If DataFrame has exactly 41 columns (features only), assign names
        if df.shape[1] == 41:
            df.columns = NSL_KDD_COLUMNS
        elif df.shape[1] >= 41:
            df.columns = NSL_KDD_COLUMNS + list(df.columns[41:])

        for idx, row in df.iterrows():
            try:
                features = row.to_dict()
                pred = self.predict(features)
                results.append({
                    "row": idx,
                    "label": pred["label"],
                    "confidence": pred["confidence"]
                })
            except Exception as e:
                results.append({"row": idx, "label": "ERROR", "confidence": 0.0})

        return results
