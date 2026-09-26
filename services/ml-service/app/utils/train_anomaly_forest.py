"""
CYBERGUARD — Unsupervised Anomaly Forest Trainer (Phase 4.4)

Trains an IsolationForest model on clean benign/background network flows
from CTU-13 training scenarios (42, 43, 44).
Serializes the fitted model to app/models/network_anomaly_forest.joblib.
"""

from pathlib import Path
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

from app.utils.ctu13_preprocessor import FEATURE_COLUMNS


def train_and_save_anomaly_forest():
    ml_service_dir = Path(__file__).resolve().parents[2]
    train_parquet = ml_service_dir / "data" / "ctu13" / "train_features.parquet"
    out_model = ml_service_dir / "app" / "models" / "network_anomaly_forest.joblib"

    print(f"Reading benign flows from {train_parquet}...")
    df = pd.read_parquet(train_parquet)
    df_benign = df[df["is_threat"] == 0]
    X_benign = df_benign[FEATURE_COLUMNS]
    print(f"Fitting IsolationForest on {len(X_benign)} clean background flows...")

    iso = IsolationForest(
        n_estimators=100,
        contamination=0.07,
        random_state=42,
        n_jobs=-1
    )
    iso.fit(X_benign)

    out_model.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(iso, out_model)
    print(f"Successfully serialized anomaly forest to {out_model} ({out_model.stat().st_size / 1024:.1f} KB)")


if __name__ == "__main__":
    train_and_save_anomaly_forest()
