"""
CYBERGUARD Recommendation Engine V1 - Production Training Pipeline
Trains the production Incident Response Recommendation Model using ONLY the real dataset
at datasets/Recommendation/incident_response_playbook_dataset.jsonl.

Strict constraints:
- Real data only, zero synthetic samples.
- Zero data leakage: fit on train only, frozen test set evaluated once.
- Artifacts saved with SHA-256 and metadata.
"""

import json
import hashlib
from pathlib import Path
from collections import Counter, defaultdict
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    accuracy_score,
    ndcg_score,
    brier_score_loss,
)

BASE_DIR = Path(__file__).resolve().parent.parent
WORKSPACE_DIR = BASE_DIR.parent.parent
DATASET_PATH = WORKSPACE_DIR / "datasets" / "Recommendation" / "incident_response_playbook_dataset.jsonl"
OUTPUT_DIR = BASE_DIR / "app" / "models" / "recommendation"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

MODEL_ARTIFACT_PATH = OUTPUT_DIR / "recommendation_classifier_v1.0.0.joblib"
METADATA_PATH = OUTPUT_DIR / "recommendation_metadata.json"
SCHEMA_PATH = OUTPUT_DIR / "recommendation_schema.json"


def compute_sha256(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def map_action_to_canonical(action_text: str) -> str:
    text = action_text.lower()
    canonical = []
    if any(k in text for k in ["isolate", "segment"]):
        canonical.append("isolate_device")
    if any(k in text for k in ["c2", "domain", "oauth"]):
        canonical.append("block_domain")
    if any(k in text for k in ["ip", "rate limit", "reroute", "ddos mitigation", "traffic"]):
        canonical.append("block_ip")
    if any(k in text for k in ["revoke", "suspend", "restrict", "lockout"]):
        canonical.append("revoke_session")
    if any(k in text for k in ["reset", "credential", "password"]):
        canonical.append("force_password_reset")
    if any(k in text for k in ["quarantine", "email"]):
        canonical.append("quarantine_email")
    if any(k in text for k in ["pod", "kill", "sanitize", "disable", "terminate"]):
        canonical.append("kill_process")
    return canonical[0] if canonical else "isolate_device"


def load_dataset():
    print(f"Loading real dataset from: {DATASET_PATH}")
    dataset_hash = compute_sha256(DATASET_PATH)
    print(f"Dataset SHA-256: {dataset_hash}")

    records = []
    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            if '"tactic","Impact"' in line:
                line = line.replace('"tactic","Impact"', '"tactic":"Impact"')
            records.append(json.loads(line))

    print(f"Loaded {len(records)} verified records from real dataset.")
    return records, dataset_hash


def build_features_and_targets(records):
    X_text = []
    y_target = []
    threat_types = []
    metadata_list = []

    for r in records:
        c_action = [s["action"] for s in r["playbook_steps"] if s["phase"] == "Containment"][0]
        target_act = map_action_to_canonical(c_action)

        threat = r.get("incident_type", "").lower()
        sev = r.get("severity", "").lower()
        asset = r.get("target_asset", "").lower()
        source = r.get("detection_source", "").lower()
        vector = r.get("initial_vector", "").lower()
        tags = " ".join(r.get("tags", []))
        tactics = " ".join([t.get("tactic", "") for t in r.get("tactics_techniques", [])]).lower()
        techniques = " ".join([t.get("technique", "") for t in r.get("tactics_techniques", [])]).lower()

        combined_text = f"{threat} {sev} {asset} {source} {vector} {tags} {tactics} {techniques}"

        X_text.append(combined_text)
        y_target.append(target_act)
        threat_types.append(threat)
        metadata_list.append({
            "incident_id": r["incident_id"],
            "incident_type": threat,
            "severity": sev,
            "target_action": target_act,
            "raw_action": c_action,
        })

    return X_text, np.array(y_target), threat_types, metadata_list


def eval_ranking_metrics(pred_prob_matrix, model_classes, y_true):
    N = len(y_true)
    top1 = 0
    top3 = 0
    top5 = 0
    mrr_list = []
    ndcg3_list = []
    ndcg5_list = []

    for i in range(N):
        true_cls = y_true[i]
        probs = pred_prob_matrix[i]
        ranked_cls = [model_classes[idx] for idx in np.argsort(-probs)]

        if ranked_cls[0] == true_cls:
            top1 += 1
        if true_cls in ranked_cls[:3]:
            top3 += 1
        if true_cls in ranked_cls[:5]:
            top5 += 1

        rank = ranked_cls.index(true_cls) + 1 if true_cls in ranked_cls else len(ranked_cls) + 1
        mrr_list.append(1.0 / rank)

        relevance = np.array([1.0 if c == true_cls else 0.0 for c in model_classes])
        ndcg3_list.append(ndcg_score(relevance.reshape(1, -1), probs.reshape(1, -1), k=3))
        ndcg5_list.append(ndcg_score(relevance.reshape(1, -1), probs.reshape(1, -1), k=5))

    pred_cls = [model_classes[np.argmax(p)] for p in pred_prob_matrix]
    macro_f1 = f1_score(y_true, pred_cls, average="macro", zero_division=0)
    weighted_f1 = f1_score(y_true, pred_cls, average="weighted", zero_division=0)

    return {
        "top1_acc": round(top1 / N, 4),
        "top3_acc": round(top3 / N, 4),
        "top5_acc": round(top5 / N, 4),
        "mrr": round(float(np.mean(mrr_list)), 4),
        "ndcg_at_3": round(float(np.mean(ndcg3_list)), 4),
        "ndcg_at_5": round(float(np.mean(ndcg5_list)), 4),
        "macro_f1": round(float(macro_f1), 4),
        "weighted_f1": round(float(weighted_f1), 4),
    }


def main():
    records, dataset_hash = load_dataset()
    X_text, y_target, threat_types, metadata = build_features_and_targets(records)

    counts = Counter(y_target)
    classes = sorted(list(counts.keys()))
    print(f"Action vocabulary ({len(classes)} classes): {classes}")
    print(f"Class distribution: {dict(counts)}")

    # Stratified split: 70% train (121), 15% val (26), 15% test (27)
    strat_y = [y if counts[y] >= 4 else "isolate_device" for y in y_target]
    indices = np.arange(len(records))

    train_idx, temp_idx = train_test_split(indices, test_size=0.30, random_state=42, stratify=strat_y)
    strat_temp = [strat_y[i] for i in temp_idx]
    strat_temp_counts = Counter(strat_temp)
    strat_temp_labels = [s if strat_temp_counts[s] >= 2 else "isolate_device" for s in strat_temp]
    val_idx, test_idx = train_test_split(temp_idx, test_size=0.50, random_state=42, stratify=strat_temp_labels)

    print(f"\nPartitions: Train={len(train_idx)}, Val={len(val_idx)}, Test={len(test_idx)}")
    assert len(set(train_idx).intersection(set(val_idx))) == 0
    assert len(set(train_idx).intersection(set(test_idx))) == 0
    assert len(set(val_idx).intersection(set(test_idx))) == 0
    print("Zero leakage verified across splits.")

    # 1. Baseline: P(action | threat_type) on training data only
    threat_action_counts = defaultdict(Counter)
    for i in train_idx:
        threat_action_counts[threat_types[i]][y_target[i]] += 1
    train_global_top = Counter(y_target[train_idx]).most_common(1)[0][0]

    def baseline_predict_proba(indices_to_pred):
        probs = []
        for i in indices_to_pred:
            t = threat_types[i]
            c_cnt = threat_action_counts[t]
            tot = sum(c_cnt.values())
            if tot > 0:
                row = [c_cnt.get(c, 0) / tot for c in classes]
            else:
                row = [1.0 if c == train_global_top else 0.0 for c in classes]
            probs.append(row)
        return np.array(probs)

    val_base_probs = baseline_predict_proba(val_idx)
    test_base_probs = baseline_predict_proba(test_idx)

    base_val_metrics = eval_ranking_metrics(val_base_probs, classes, y_target[val_idx])
    base_test_metrics = eval_ranking_metrics(test_base_probs, classes, y_target[test_idx])
    print(f"\nBaseline Validation Metrics: {base_val_metrics}")
    print(f"Baseline Test Metrics: {base_test_metrics}")

    # 2. Production Model Training: TF-IDF + Random Forest Classifier (fitted on train only)
    tfidf = TfidfVectorizer(max_features=120, ngram_range=(1, 2))
    X_train_vec = tfidf.fit_transform([X_text[i] for i in train_idx])
    X_val_vec = tfidf.transform([X_text[i] for i in val_idx])
    X_test_vec = tfidf.transform([X_text[i] for i in test_idx])

    rf = RandomForestClassifier(n_estimators=100, max_depth=6, random_state=42)
    rf.fit(X_train_vec, y_target[train_idx])

    val_rf_probs = rf.predict_proba(X_val_vec)
    test_rf_probs = rf.predict_proba(X_test_vec)

    rf_val_metrics = eval_ranking_metrics(val_rf_probs, rf.classes_, y_target[val_idx])
    rf_test_metrics = eval_ranking_metrics(test_rf_probs, rf.classes_, y_target[test_idx])
    print(f"\nRandom Forest Validation Metrics: {rf_val_metrics}")
    print(f"Random Forest Test Metrics: {rf_test_metrics}")

    # Test set per-action metrics
    y_test_pred = rf.predict(X_test_vec)
    cls_report = classification_report(
        y_target[test_idx], y_test_pred, target_names=rf.classes_, output_dict=True, zero_division=0
    )
    conf_mat = confusion_matrix(y_target[test_idx], y_test_pred, labels=rf.classes_).tolist()

    # Brier score
    brier_scores = []
    for idx, cls_name in enumerate(rf.classes_):
        y_bin = (y_target[test_idx] == cls_name).astype(int)
        bs = brier_score_loss(y_bin, test_rf_probs[:, idx])
        brier_scores.append(float(bs))
    mean_brier = float(np.mean(brier_scores))
    print(f"Mean Brier Score: {mean_brier:.4f}")

    # Package pipeline
    pipeline_artifact = {
        "model_version": "v1.0.0",
        "vectorizer": tfidf,
        "classifier": rf,
        "action_classes": list(rf.classes_),
        "vocabulary_size": len(tfidf.vocabulary_),
    }

    # Save artifact
    joblib.dump(pipeline_artifact, MODEL_ARTIFACT_PATH)
    artifact_hash = compute_sha256(MODEL_ARTIFACT_PATH)
    file_size_bytes = MODEL_ARTIFACT_PATH.stat().st_size
    print(f"\nSaved production artifact to: {MODEL_ARTIFACT_PATH}")
    print(f"Artifact SHA-256: {artifact_hash} ({file_size_bytes} bytes)")

    # Metadata
    metadata_doc = {
        "model_name": "recommendation_classifier_v1.0.0",
        "model_version": "v1.0.0",
        "created_at": "2026-10-06T20:00:00Z",
        "framework": "scikit-learn",
        "architecture": "TfidfVectorizer + RandomForestClassifier",
        "dataset_path": str(DATASET_PATH),
        "dataset_sha256": dataset_hash,
        "dataset_size_records": len(records),
        "splits": {
            "train_count": len(train_idx),
            "val_count": len(val_idx),
            "test_count": len(test_idx),
            "split_ratio": "70/15/15",
            "zero_leakage_verified": True
        },
        "action_classes": list(rf.classes_),
        "validation_metrics": rf_val_metrics,
        "baseline_validation_metrics": base_val_metrics,
        "frozen_test_metrics": rf_test_metrics,
        "baseline_test_metrics": base_test_metrics,
        "per_action_test_report": cls_report,
        "confusion_matrix": conf_mat,
        "mean_brier_score": mean_brier,
        "artifact_sha256": artifact_hash,
        "file_size_bytes": file_size_bytes,
        "rollback_strategy": "RETAIN_CURRENT_V1"
    }

    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata_doc, f, indent=2)
    print(f"Saved training metadata to: {METADATA_PATH}")

    # Schema
    schema_doc = {
        "schema_version": "1.0.0",
        "input_features": [
            "threat_type",
            "severity",
            "target_asset",
            "detection_source",
            "initial_vector",
            "mitre_tactics",
            "mitre_techniques",
            "tags"
        ],
        "action_classes": list(rf.classes_),
        "ranking_method": "Predictive probability distribution over canonical incident-response actions",
        "safety_guardrails": {
            "destructive_actions_require_approval": True,
            "false_positive_score_discount_enabled": True
        }
    }

    with open(SCHEMA_PATH, "w", encoding="utf-8") as f:
        json.dump(schema_doc, f, indent=2)
    print(f"Saved feature schema to: {SCHEMA_PATH}")

    print("\nRECOMMENDATION MODEL V1 TRAINING & ARTIFACT GENERATION COMPLETED SUCCESSFULLY.")


if __name__ == "__main__":
    main()
