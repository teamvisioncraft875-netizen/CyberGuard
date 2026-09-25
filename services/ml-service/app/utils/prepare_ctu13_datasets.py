"""
CYBERGUARD — CTU-13 Dataset Preparation Pipeline

Processes raw CTU-13 binetflow files in chunks without exhausting RAM.
- Scenarios 42, 43, 44 -> train_features.parquet
- Scenario 45 -> test_features.parquet (held-out evaluation)

Sampling Strategy:
- Retains 100% of scarce Botnet threat samples to preserve rare threat signatures.
- Uniformly downsamples massive background/benign traffic (1.5% - 2.0%) using a fixed random seed.
- Guarantees zero data leakage between training and held-out test scenarios.
"""

import os
import sys
from pathlib import Path

# Ensure ml-service root is in sys.path
ml_service_dir = Path(__file__).resolve().parents[2]
if str(ml_service_dir) not in sys.path:
    sys.path.insert(0, str(ml_service_dir))

from typing import Tuple, List, Optional
import pandas as pd
import numpy as np

from app.utils.ctu13_preprocessor import CTU13Preprocessor, FEATURE_COLUMNS



def process_scenario_file(
    file_path: Path,
    benign_sample_ratio: float = 0.02,
    chunk_size: int = 100000,
    random_state: int = 42,
) -> pd.DataFrame:
    """
    Streams a single CTU-13 binetflow file in chunks.
    Collects all botnet flows and a controlled sample of benign flows.
    """
    preprocessor = CTU13Preprocessor()
    collected_chunks: List[pd.DataFrame] = []
    rng = np.random.RandomState(random_state)

    total_rows = 0
    total_threats = 0
    total_benign = 0

    print(f"[*] Processing {file_path.name} (chunk size: {chunk_size:,})...")

    # Read file in chunks
    for chunk in pd.read_csv(file_path, chunksize=chunk_size, low_memory=False):
        total_rows += len(chunk)
        X_chunk, y_chunk = preprocessor.transform(chunk)
        chunk_df = X_chunk.copy()
        chunk_df["is_threat"] = y_chunk.values

        # Separate threats from benign
        threat_mask = chunk_df["is_threat"] == 1
        threats = chunk_df[threat_mask]
        benign = chunk_df[~threat_mask]

        total_threats += len(threats)

        # Sample benign traffic
        if not benign.empty and benign_sample_ratio < 1.0:
            sample_size = int(np.ceil(len(benign) * benign_sample_ratio))
            sample_indices = rng.choice(benign.index, size=sample_size, replace=False)
            sampled_benign = benign.loc[sample_indices]
        else:
            sampled_benign = benign

        total_benign += len(sampled_benign)

        if not threats.empty:
            collected_chunks.append(threats)
        if not sampled_benign.empty:
            collected_chunks.append(sampled_benign)

    result_df = pd.concat(collected_chunks, ignore_index=True) if collected_chunks else pd.DataFrame()
    print(
        f"    -> Finished {file_path.name}: {total_rows:,} raw flows | "
        f"Kept: {len(result_df):,} ({total_threats:,} botnet, {total_benign:,} benign)"
    )
    return result_df


def prepare_ctu13_datasets(
    ctu13_dir: Path,
    output_dir: Path,
    benign_sample_ratio: float = 0.02,
    chunk_size: int = 100000,
    random_state: int = 42,
) -> Tuple[Path, Path]:
    """
    Prepares train_features.parquet (scenarios 42, 43, 44)
    and test_features.parquet (scenario 45).
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    train_output = output_dir / "train_features.parquet"
    test_output = output_dir / "test_features.parquet"

    train_files = [
        ctu13_dir / "capture20110810_botnet_42.binetflow.txt",
        ctu13_dir / "capture20110811_botnet_43.binetflow.txt",
        ctu13_dir / "capture20110812_botnet_44.binetflow.txt",
    ]
    test_file = ctu13_dir / "capture20110815_botnet_45.binetflow.txt"

    # 1. Build Training Set
    train_dfs: List[pd.DataFrame] = []
    print("\n=== Building Training Set (Scenarios 42, 43, 44) ===")
    for f in train_files:
        if not f.exists():
            raise FileNotFoundError(f"Missing required training scenario file: {f}")
        df_scenario = process_scenario_file(
            f, benign_sample_ratio=benign_sample_ratio, chunk_size=chunk_size, random_state=random_state
        )
        train_dfs.append(df_scenario)

    train_combined = pd.concat(train_dfs, ignore_index=True).sample(frac=1.0, random_state=random_state).reset_index(drop=True)
    
    # Save training parquet
    try:
        train_combined.to_parquet(train_output, index=False, engine="pyarrow")
        print(f"[+] Saved training dataset: {train_output} ({train_output.stat().st_size / (1024*1024):.2f} MB, {len(train_combined):,} rows)")
    except Exception as e:
        # Fallback to CSV if parquet fails
        train_output = output_dir / "train_features.csv"
        train_combined.to_csv(train_output, index=False)
        print(f"[!] Parquet fallback to CSV: {train_output}")

    # 2. Build Held-out Evaluation Set
    print("\n=== Building Held-out Evaluation Set (Scenario 45) ===")
    if not test_file.exists():
        raise FileNotFoundError(f"Missing required evaluation scenario file: {test_file}")
    
    # Use 3% benign for test set to ensure solid statistical power
    test_df = process_scenario_file(
        test_file, benign_sample_ratio=max(benign_sample_ratio, 0.03), chunk_size=chunk_size, random_state=random_state + 1
    )
    test_combined = test_df.sample(frac=1.0, random_state=random_state + 1).reset_index(drop=True)

    try:
        test_combined.to_parquet(test_output, index=False, engine="pyarrow")
        print(f"[+] Saved evaluation dataset: {test_output} ({test_output.stat().st_size / (1024*1024):.2f} MB, {len(test_combined):,} rows)")
    except Exception as e:
        test_output = output_dir / "test_features.csv"
        test_combined.to_csv(test_output, index=False)
        print(f"[!] Parquet fallback to CSV: {test_output}")

    return train_output, test_output


if __name__ == "__main__":
    base_dir = Path(__file__).resolve().parents[4]  # repo root
    ctu13_path = base_dir / "datasets" / "ctu13"
    out_path = Path(__file__).resolve().parents[2] / "data" / "ctu13"

    print(f"Repository Root: {base_dir}")
    print(f"CTU-13 Directory: {ctu13_path}")
    print(f"Output Directory: {out_path}")

    prepare_ctu13_datasets(ctu13_path, out_path)
