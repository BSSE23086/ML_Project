"""
Model Trainer Module
Trains both supervised (Random Forest, SVM, Logistic Regression)
and unsupervised (K-Means, Isolation Forest) models on NSL-KDD dataset.
Authors: Muhammad Tayyab (BSSE23018), Tehreem Mazhar (BSSE23086)
"""

import pandas as pd
import numpy as np
import os
import json
import pickle
import warnings
warnings.filterwarnings("ignore")

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.cluster import KMeans
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                              f1_score, classification_report)

# NSL-KDD dataset column names (41 features + label + difficulty)
NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty"
]

# Map attack categories to binary label: normal=0, attack=1
ATTACK_MAPPING = {
    "normal": 0,
    # DoS attacks
    "back": 1, "land": 1, "neptune": 1, "pod": 1, "smurf": 1, "teardrop": 1,
    # Probe attacks
    "ipsweep": 1, "nmap": 1, "portsweep": 1, "satan": 1,
    # R2L attacks
    "ftp_write": 1, "guess_passwd": 1, "imap": 1, "multihop": 1, "phf": 1,
    "spy": 1, "warezclient": 1, "warezmaster": 1,
    # U2R attacks
    "buffer_overflow": 1, "loadmodule": 1, "perl": 1, "rootkit": 1
}


class ModelTrainer:
    """
    Handles data loading, preprocessing, model training,
    hyperparameter optimization, and evaluation.
    """

    def __init__(self, data_path="data/KDDTrain+.txt"):
        self.data_path = data_path
        self.model_dir = "models/"
        self.scaler = StandardScaler()
        self.label_encoders = {}
        os.makedirs(self.model_dir, exist_ok=True)

    # -----------------------------------------------------------------------
    # DATA LOADING & PREPROCESSING
    # -----------------------------------------------------------------------

    def load_data(self):
        """
        Load NSL-KDD dataset. If file not found, generate synthetic data
        for demonstration purposes.
        """
        if os.path.exists(self.data_path):
            print(f"[INFO] Loading dataset from {self.data_path}")
            df = pd.read_csv(self.data_path, header=None, names=NSL_KDD_COLUMNS)
        else:
            print("[WARNING] Dataset not found. Generating synthetic data for demo.")
            df = self._generate_synthetic_data(5000)
        return df

    def _generate_synthetic_data(self, n_samples=5000):
        """
        Generate synthetic NSL-KDD-like data for demonstration.
        Creates realistic feature distributions for normal and attack traffic.
        """
        np.random.seed(42)
        n_normal = int(n_samples * 0.6)
        n_attack = n_samples - n_normal

        protocols = ["tcp", "udp", "icmp"]
        services = ["http", "ftp", "smtp", "ssh", "dns", "pop3", "telnet", "other"]
        flags = ["SF", "S0", "REJ", "RSTO", "RSTR", "SH", "OTH"]

        def make_rows(n, label, attack_type=False):
            rows = []
            for _ in range(n):
                row = {
                    "duration": np.random.exponential(50) if not attack_type else np.random.exponential(5),
                    "protocol_type": np.random.choice(protocols, p=[0.6, 0.3, 0.1]),
                    "service": np.random.choice(services),
                    "flag": np.random.choice(flags, p=[0.7, 0.1, 0.05, 0.05, 0.04, 0.03, 0.03]),
                    "src_bytes": np.random.randint(0, 5000) if not attack_type else np.random.randint(0, 100),
                    "dst_bytes": np.random.randint(0, 10000) if not attack_type else 0,
                    "land": 0, "wrong_fragment": 0, "urgent": 0,
                    "hot": np.random.randint(0, 10),
                    "num_failed_logins": np.random.randint(0, 3),
                    "logged_in": np.random.randint(0, 2),
                    "num_compromised": 0, "root_shell": 0, "su_attempted": 0,
                    "num_root": 0, "num_file_creations": 0, "num_shells": 0,
                    "num_access_files": 0, "num_outbound_cmds": 0,
                    "is_host_login": 0, "is_guest_login": 0,
                    "count": np.random.randint(1, 512),
                    "srv_count": np.random.randint(1, 512),
                    "serror_rate": np.random.uniform(0, 0.2) if not attack_type else np.random.uniform(0.8, 1.0),
                    "srv_serror_rate": np.random.uniform(0, 0.2),
                    "rerror_rate": np.random.uniform(0, 0.1),
                    "srv_rerror_rate": np.random.uniform(0, 0.1),
                    "same_srv_rate": np.random.uniform(0.5, 1.0),
                    "diff_srv_rate": np.random.uniform(0, 0.5),
                    "srv_diff_host_rate": np.random.uniform(0, 0.5),
                    "dst_host_count": np.random.randint(1, 255),
                    "dst_host_srv_count": np.random.randint(1, 255),
                    "dst_host_same_srv_rate": np.random.uniform(0, 1),
                    "dst_host_diff_srv_rate": np.random.uniform(0, 1),
                    "dst_host_same_src_port_rate": np.random.uniform(0, 1),
                    "dst_host_srv_diff_host_rate": np.random.uniform(0, 1),
                    "dst_host_serror_rate": np.random.uniform(0, 0.2) if not attack_type else np.random.uniform(0.8, 1.0),
                    "dst_host_srv_serror_rate": np.random.uniform(0, 0.2),
                    "dst_host_rerror_rate": np.random.uniform(0, 0.1),
                    "dst_host_srv_rerror_rate": np.random.uniform(0, 0.1),
                    "label": label,
                    "difficulty": np.random.randint(1, 21)
                }
                rows.append(row)
            return rows

        normal_rows = make_rows(n_normal, "normal", attack_type=False)
        attack_rows = make_rows(n_attack, "neptune", attack_type=True)
        df = pd.DataFrame(normal_rows + attack_rows)
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        return df

    def preprocess(self, df):
        """
        Encode categorical features, scale numeric features,
        and create binary labels (normal=0, attack=1).
        """
        print("[INFO] Preprocessing data...")
        df = df.copy()

        # Drop difficulty column (not a feature)
        if "difficulty" in df.columns:
            df.drop("difficulty", axis=1, inplace=True)

        # --- Encode categorical columns ---
        categorical_cols = ["protocol_type", "service", "flag"]
        for col in categorical_cols:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))
            self.label_encoders[col] = le  # Save for inference time

        # --- Create binary label ---
        df["binary_label"] = df["label"].apply(
            lambda x: ATTACK_MAPPING.get(str(x).strip().lower(), 1)
        )

        # --- Extract features (X) and labels (y) ---
        feature_cols = [c for c in df.columns if c not in ["label", "binary_label"]]
        X = df[feature_cols].values.astype(float)
        y = df["binary_label"].values

        # --- Scale features using StandardScaler ---
        X_scaled = self.scaler.fit_transform(X)

        # Save feature column names for inference
        self.feature_cols = feature_cols
        print(f"[INFO] Dataset shape: {X_scaled.shape}, Attack rate: {y.mean():.2%}")
        return X_scaled, y

    # -----------------------------------------------------------------------
    # MODEL TRAINING
    # -----------------------------------------------------------------------

    def train_random_forest(self, X_train, y_train):
        """
        Train Random Forest with GridSearchCV hyperparameter optimization.
        Random Forest excels at handling mixed feature types and provides
        feature importance rankings — ideal for intrusion detection.
        """
        print("[INFO] Training Random Forest with HPO...")
        param_grid = {
            "n_estimators": [100, 200],
            "max_depth": [10, 20, None],
            "min_samples_split": [2, 5]
        }
        # 3-fold CV to balance speed and reliability
        rf = GridSearchCV(
            RandomForestClassifier(random_state=42, n_jobs=-1),
            param_grid, cv=3, scoring="f1", n_jobs=-1, verbose=0
        )
        rf.fit(X_train, y_train)
        print(f"[INFO] Best RF params: {rf.best_params_}")
        return rf.best_estimator_

    def train_svm(self, X_train, y_train):
        """
        Train SVM with RBF kernel. SVMs are effective in high-dimensional spaces
        and robust against overfitting. Uses a subset for speed.
        """
        print("[INFO] Training SVM...")
        # Use subset for training speed; SVM is O(n^2) memory
        max_samples = min(10000, len(X_train))
        idx = np.random.choice(len(X_train), max_samples, replace=False)
        svm = SVC(kernel="rbf", C=1.0, gamma="scale", probability=True, random_state=42)
        svm.fit(X_train[idx], y_train[idx])
        return svm

    def train_logistic_regression(self, X_train, y_train):
        """
        Train Logistic Regression. Fast, interpretable baseline model
        used for comparison against ensemble methods.
        """
        print("[INFO] Training Logistic Regression...")
        lr = LogisticRegression(max_iter=1000, random_state=42, n_jobs=-1)
        lr.fit(X_train, y_train)
        return lr

    def train_isolation_forest(self, X_train):
        """
        Train Isolation Forest (unsupervised anomaly detection).
        Does NOT require labels — detects anomalies by isolating outliers.
        Contamination parameter = expected fraction of attacks in dataset.
        """
        print("[INFO] Training Isolation Forest (unsupervised)...")
        iso = IsolationForest(
            n_estimators=100,
            contamination=0.4,  # ~40% of NSL-KDD is attacks
            random_state=42,
            n_jobs=-1
        )
        iso.fit(X_train)
        return iso

    def train_kmeans(self, X_train):
        """
        Train K-Means clustering (unsupervised).
        Groups traffic into 2 clusters: normal vs anomalous.
        Cluster assignment is post-hoc mapped to normal/attack.
        """
        print("[INFO] Training K-Means (unsupervised)...")
        kmeans = KMeans(n_clusters=2, random_state=42, n_init=10)
        kmeans.fit(X_train)
        return kmeans

    # -----------------------------------------------------------------------
    # EVALUATION
    # -----------------------------------------------------------------------

    def evaluate_supervised(self, model, X_test, y_test, name):
        """Compute accuracy, precision, recall, F1 for supervised models."""
        y_pred = model.predict(X_test)
        metrics = {
            "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
            "precision": round(float(precision_score(y_test, y_pred, zero_division=0)), 4),
            "recall": round(float(recall_score(y_test, y_pred, zero_division=0)), 4),
            "f1_score": round(float(f1_score(y_test, y_pred, zero_division=0)), 4)
        }
        print(f"[RESULT] {name}: {metrics}")
        return metrics

    def evaluate_isolation_forest(self, model, X_test, y_test):
        """
        Evaluate Isolation Forest.
        Isolation Forest returns +1 (normal) and -1 (anomaly).
        We flip the sign to match our convention: 1=attack, 0=normal.
        """
        raw_pred = model.predict(X_test)
        # -1 (anomaly) → 1 (attack), +1 (normal) → 0
        y_pred = np.where(raw_pred == -1, 1, 0)
        metrics = {
            "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
            "precision": round(float(precision_score(y_test, y_pred, zero_division=0)), 4),
            "recall": round(float(recall_score(y_test, y_pred, zero_division=0)), 4),
            "f1_score": round(float(f1_score(y_test, y_pred, zero_division=0)), 4)
        }
        print(f"[RESULT] Isolation Forest: {metrics}")
        return metrics

    def evaluate_kmeans(self, model, X_test, y_test):
        """
        Evaluate K-Means by mapping cluster labels to attack/normal.
        The cluster with higher mean attack rate = attack cluster.
        """
        cluster_labels = model.predict(X_test)
        # Map cluster → binary label based on majority vote
        mapping = {}
        for c in np.unique(cluster_labels):
            mask = cluster_labels == c
            mapping[c] = 1 if y_test[mask].mean() >= 0.5 else 0
        y_pred = np.array([mapping[c] for c in cluster_labels])
        metrics = {
            "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
            "precision": round(float(precision_score(y_test, y_pred, zero_division=0)), 4),
            "recall": round(float(recall_score(y_test, y_pred, zero_division=0)), 4),
            "f1_score": round(float(f1_score(y_test, y_pred, zero_division=0)), 4)
        }
        print(f"[RESULT] K-Means: {metrics}")
        return metrics

    # -----------------------------------------------------------------------
    # MAIN TRAINING PIPELINE
    # -----------------------------------------------------------------------

    def train_all_models(self):
        """
        Full training pipeline:
        1. Load data
        2. Preprocess
        3. Train all 5 models
        4. Evaluate and compare
        5. Save best supervised model + all models
        6. Save metrics JSON for dashboard

        MODEL SELECTION LOGIC:
        Random Forest is selected as the primary model because:
        - Highest F1-score on intrusion detection benchmarks
        - Handles class imbalance natively
        - Provides feature importance for explainability
        - Robust to noisy/irrelevant features
        """
        df = self.load_data()
        X, y = self.preprocess(df)

        # Train/test split with stratification to preserve class ratio
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        all_metrics = {}

        # --- Supervised Models ---
        rf_model = self.train_random_forest(X_train, y_train)
        all_metrics["Random Forest"] = self.evaluate_supervised(rf_model, X_test, y_test, "Random Forest")

        svm_model = self.train_svm(X_train, y_train)
        all_metrics["SVM"] = self.evaluate_supervised(svm_model, X_test, y_test, "SVM")

        lr_model = self.train_logistic_regression(X_train, y_train)
        all_metrics["Logistic Regression"] = self.evaluate_supervised(lr_model, X_test, y_test, "Logistic Regression")

        # --- Unsupervised Models ---
        iso_model = self.train_isolation_forest(X_train)
        all_metrics["Isolation Forest"] = self.evaluate_isolation_forest(iso_model, X_test, y_test)

        km_model = self.train_kmeans(X_train)
        all_metrics["K-Means"] = self.evaluate_kmeans(km_model, X_test, y_test)

        # --- Save all models and preprocessing artifacts ---
        self._save_models(rf_model, svm_model, lr_model, iso_model, km_model)
        self._save_metrics(all_metrics)

        print("\n[INFO] Training complete. Random Forest selected as primary model.")
        return all_metrics

    def _save_models(self, rf, svm, lr, iso, km):
        """Persist all trained models and preprocessing objects to disk."""
        models = {
            "random_forest.pkl": rf,
            "svm.pkl": svm,
            "logistic_regression.pkl": lr,
            "isolation_forest.pkl": iso,
            "kmeans.pkl": km,
            "scaler.pkl": self.scaler,
            "label_encoders.pkl": self.label_encoders,
        }
        for filename, obj in models.items():
            with open(os.path.join(self.model_dir, filename), "wb") as f:
                pickle.dump(obj, f)
            print(f"[INFO] Saved {filename}")

        # Save feature column list for inference
        with open(os.path.join(self.model_dir, "feature_cols.json"), "w") as f:
            json.dump(self.feature_cols, f)

    def _save_metrics(self, metrics):
        """Save evaluation metrics as JSON for the dashboard."""
        with open(os.path.join(self.model_dir, "metrics.json"), "w") as f:
            json.dump(metrics, f, indent=2)
        print("[INFO] Metrics saved to models/metrics.json")


# Allow running standalone for testing
if __name__ == "__main__":
    trainer = ModelTrainer()
    results = trainer.train_all_models()
    print("\n=== FINAL RESULTS ===")
    for model, m in results.items():
        print(f"{model:25s} | Acc: {m['accuracy']:.4f} | F1: {m['f1_score']:.4f}")
