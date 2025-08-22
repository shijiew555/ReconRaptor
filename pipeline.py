#!/usr/bin/env python3
"""
Prototype implementation for reconnaissance detection workflow. 

Stage 1: Suspicious Log Gathering
  1) Filter CloudTrail logs to those with readOnly == True
  2) Encode each log into a 13-dimensional numeric feature vector using the
     encodings described in the design doc table:
       - eventName:           categorical → hashing trick (single numeric hash)
       - eventSource:         categorical → hashing trick
       - eventCategory:       categorical → hashing trick
       - eventType:           categorical → hashing trick
       - userIdentity:        nested json → extract userIdentity.type → hashing trick
       - sessionContext:      nested json → extract sessionContext.sessionIssuer.type → hashing trick
       - recipientAccountId:  categorical → hashing trick (string form)
       - sourceIPAddress:     IP → convert IPv4 to 32-bit integer (IPv6/other → hash)
       - awsRegion:           categorical → hashing trick
       - userAgent:           text → combine length and first-4-chars hash into a single number
       - errorCode:           categorical → binary presence (1 if present else 0)
       - requestParameters:   nested json → number of keys if dict else 0
       - responseElements:    nested json → length of json string representation

     Notes on the userAgent encoding: the recommended approach is
     "length + hash prefix"; to keep the overall feature vector to 13
     dimensions we combine these two signals into one numeric value:
     combined = length * 65536 + (hash(prefix_4) & 0xFFFF)

  3) Cluster the vectors with DBSCAN. After clustering, print metadata for each
     discovered cluster (targeting ~24 clusters depending on parameters):
       - cluster id, size, error rate (fraction with errorCode present)
       - list of eventName values in this cluster
     Finally, select the top 3 clusters with the highest error rate as
     "suspicious".

Stage 2: Timeframe Analysis (Sliding Window)
  - Build a 1-hour sliding window over the (readOnly) logs timeline.
  - For each window, compute suspicious_density = suspicious_count / total_count.
  - Keep windows with density >= 0.10 (10%).
  - For each kept timeframe, report:
      * confidence = suspicious_density
      * identities = list of tuples (sourceIPAddress, IAM user or ARN, userAgent, OS guess)
      * example APIs = set of eventName in suspicious logs in this timeframe


"""

from __future__ import annotations

import argparse
import json
import os
import socket
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler


# ---------------------------------- File Loading Functions ----------------------------------


def load_cloudtrail_dir(logs_dir: str) -> pd.DataFrame:
    """Load CloudTrail logs from a directory of .json files into a DataFrame.

    Supports files that are either JSON Lines or standard CloudTrail JSON with
    top-level  or a top-level list of records.
    """
    records: List[Dict[str, Any]] = []

    filenames = [
        os.path.join(logs_dir, name)
        for name in sorted(os.listdir(logs_dir))
        if name.lower().endswith(".json")
    ]
    for path in filenames:
        # Try JSON Lines, but only accept if chunks look like per-event rows
        try:
            appended = 0
            for chunk in pd.read_json(path, lines=True, chunksize=100_000):
                # Accept JSON Lines only if it looks like per-event rows
                if "eventName" not in chunk.columns:
                    appended = 0
                    break
                records.extend(chunk.to_dict(orient="records"))
                appended += len(chunk)
            # If JSON Lines yielded valid per-event rows, skip fallback
            if appended > 0:
                continue
        except ValueError:
            pass
        except Exception:
            pass

        # Fallback to standard JSON
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict) and "Records" in data and isinstance(data["Records"], list):
                records.extend([r for r in data["Records"] if isinstance(r, dict)])
            elif isinstance(data, list):
                records.extend([r for r in data if isinstance(r, dict)])
            else:
                # Try to find a plausible list
                if isinstance(data, dict):
                    for v in data.values():
                        if isinstance(v, list) and v and isinstance(v[0], dict):
                            records.extend([r for r in v if isinstance(r, dict)])
                            break
        except Exception:
            # Skip files that fail to parse entirely
            continue

    if not records:
        return pd.DataFrame()

    df = pd.DataFrame.from_records(records)

    # Ensure eventTime is parsed as datetime if present
    if "eventTime" in df.columns:
        try:
            df["eventTime"] = pd.to_datetime(df["eventTime"], errors="coerce")
        except Exception:
            df["eventTime"] = pd.to_datetime(df["eventTime"], errors="coerce")

    return df


# ----------------------------- Log Attribute Encoding Functions ------------------------------


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    try:
        return str(value)
    except Exception:
        return ""


def _hash32(value: str) -> int:
    # Deterministic 32-bit signed hash
    h = hash(value) & 0xFFFFFFFF
    if h >= 0x80000000:
        h = -((~h & 0xFFFFFFFF) + 1)
    return h


def _ip_to_int(ip: Any) -> int:
    s = _safe_str(ip)
    try:
        # Try IPv4
        return struct.unpack("!I", socket.inet_aton(s))[0]
    except Exception:
        return _hash32(s)


def _user_agent_to_num(ua: Any) -> int:
    s = _safe_str(ua)
    length = len(s)
    prefix = s[:4]
    prefix_hash_low16 = _hash32(prefix) & 0xFFFF
    # Combine into a single numeric to preserve 13-D total
    return int(length) * 65536 + int(prefix_hash_low16)


def _json_length(value: Any) -> int:
    try:
        return len(json.dumps(value, default=str))
    except Exception:
        return 0


def _num_keys(value: Any) -> int:
    return len(value.keys()) if isinstance(value, dict) else 0


def encode_row_to_vector(row: pd.Series) -> np.ndarray:
    """Encode a single CloudTrail record to a 13-dimensional vector."""
    event_name = _hash32(_safe_str(row.get("eventName")))
    event_source = _hash32(_safe_str(row.get("eventSource")))
    event_category = _hash32(_safe_str(row.get("eventCategory")))
    event_type = _hash32(_safe_str(row.get("eventType")))

    user_identity = row.get("userIdentity") or {}
    ui_type = _safe_str(user_identity.get("type")) if isinstance(user_identity, dict) else _safe_str(user_identity)
    user_identity_enc = _hash32(ui_type)

    session_ctx = row.get("sessionContext") or {}
    sess_issuer_type = ""
    if isinstance(session_ctx, dict):
        issuer = session_ctx.get("sessionIssuer")
        if isinstance(issuer, dict):
            sess_issuer_type = _safe_str(issuer.get("type"))
    session_context_enc = _hash32(sess_issuer_type)

    recipient_acct = _hash32(_safe_str(row.get("recipientAccountId")))
    source_ip = _ip_to_int(row.get("sourceIPAddress"))
    aws_region = _hash32(_safe_str(row.get("awsRegion")))
    user_agent_num = _user_agent_to_num(row.get("userAgent"))
    error_code_present = 1 if _safe_str(row.get("errorCode")) else 0
    request_param_count = _num_keys(row.get("requestParameters"))
    response_len = _json_length(row.get("responseElements"))

    return np.array(
        [
            float(event_name),
            float(event_source),
            float(event_category),
            float(event_type),
            float(user_identity_enc),
            float(session_context_enc),
            float(recipient_acct),
            float(source_ip),
            float(aws_region),
            float(user_agent_num),
            float(error_code_present),
            float(request_param_count),
            float(response_len),
        ],
        dtype=np.float64,
    )


def encode_dataframe(df: pd.DataFrame) -> np.ndarray:
    """Encode all rows to a matrix of shape (n_samples, 13)."""
    if df.empty:
        return np.empty((0, 13), dtype=np.float64)
    vectors = [encode_row_to_vector(row) for _, row in df.iterrows()]
    return np.vstack(vectors) if vectors else np.empty((0, 13), dtype=np.float64)


# ----------------------------- Clustering & Post-processing Functions ------------------------------------


def cluster_dbscan(features: np.ndarray, eps: float, min_samples: int) -> np.ndarray:
    if features.size == 0:
        return np.empty((0,), dtype=int)
    scaler = StandardScaler()
    scaled = scaler.fit_transform(features)
    model = DBSCAN(eps=eps, min_samples=min_samples, n_jobs=-1)
    labels = model.fit_predict(scaled)
    return labels


def print_cluster_metadata(df: pd.DataFrame, labels: np.ndarray, limit_event_names: int = 25) -> None:
    if labels.size == 0:
        print("No clusters to display.")
        return
    df = df.copy()
    df["cluster"] = labels
    valid_labels = [lbl for lbl in sorted(df["cluster"].unique()) if lbl != -1]
    print(f"Discovered {len(valid_labels)} clusters (excluding noise).")
    total = len(df)
    noise_count = int((df["cluster"] == -1).sum())
    clustered_count = int(total - noise_count)
    print(f"Clustered logs: {clustered_count}, Noise logs: {noise_count} (total: {total})")
    for lbl in valid_labels:
        sub = df[df["cluster"] == lbl]
        size = len(sub)
        if size == 0:
            continue
        error_rate = float(sub["errorCode"].notna().mean())
        unique_event_names = sorted(set(_safe_str(x) for x in sub.get("eventName", [])))
        if len(unique_event_names) > limit_event_names:
            shown = unique_event_names[:limit_event_names]
            unique_event_names_str = f"{shown} ... (+{len(unique_event_names)-len(shown)} more)"
        else:
            unique_event_names_str = str(unique_event_names)
        print(
            f"Cluster {lbl}: size={size}, error_rate={error_rate:.2%}, eventNames={unique_event_names_str}"
        )


def select_top_suspicious_clusters(df: pd.DataFrame, labels: np.ndarray, top_k: int = 3) -> Tuple[pd.DataFrame, List[int]]:
    df = df.copy()
    df["cluster"] = labels
    cluster_stats: List[Tuple[int, float, int]] = []  # (label, error_rate, size)
    for lbl, sub in df[df["cluster"] != -1].groupby("cluster"):
        size = len(sub)
        if size == 0:
            continue
        error_rate = float(sub["errorCode"].notna().mean())
        cluster_stats.append((int(lbl), error_rate, size))

    # Sort by error rate desc, then size desc for stability
    cluster_stats.sort(key=lambda x: (x[1], x[2]), reverse=True)
    chosen_labels = [lbl for lbl, _, _ in cluster_stats[:top_k]]
    suspicious_df = df[df["cluster"].isin(chosen_labels)].copy()
    return suspicious_df, chosen_labels


# ----------------------------- Timeframe Selection & Analysis Functions ----------------------------


def _guess_os_from_user_agent(ua: str) -> str:
    s = (ua or "").lower()
    if "windows" in s:
        return "Windows"
    if "mac os" in s or "macintosh" in s or "darwin" in s or "os x" in s:
        return "Mac"
    if "linux" in s:
        return "Linux"
    if "android" in s:
        return "Android"
    if "iphone" in s or "ios" in s or "ipad" in s:
        return "iOS"
    return "Unknown"


@dataclass
class TimeframeSummary:
    start: pd.Timestamp
    end: pd.Timestamp
    confidence: float
    identities: List[Tuple[str, str, str, str]]  # (ip, iam, user-agent, os)
    example_apis: List[str]


def analyze_timeframes(
    df_all: pd.DataFrame,
    df_suspicious: pd.DataFrame,
    window_minutes: int = 60,
    density_threshold: float = 0.10,
) -> List[TimeframeSummary]:
    if df_all.empty or "eventTime" not in df_all.columns:
        return []

    # Build per-minute time series for total and suspicious counts
    all_ts = (
        df_all.dropna(subset=["eventTime"]).set_index("eventTime").sort_index()
    )
    susp_ts = (
        df_suspicious.dropna(subset=["eventTime"]).set_index("eventTime").sort_index()
    )

    total_per_min = all_ts["eventName"].resample("1min").count()
    susp_per_min = susp_ts["eventName"].resample("1min").count()
    # Align
    idx = total_per_min.index.union(susp_per_min.index)
    total_per_min = total_per_min.reindex(idx, fill_value=0)
    susp_per_min = susp_per_min.reindex(idx, fill_value=0)

    # Rolling window sums
    window = f"{window_minutes}min"
    total_win = total_per_min.rolling(window=window, min_periods=1).sum()
    susp_win = susp_per_min.rolling(window=window, min_periods=1).sum()
    density = (susp_win / total_win).fillna(0.0)

    # Identify contiguous intervals above threshold
    above = density >= density_threshold
    summaries: List[TimeframeSummary] = []
    if above.any():
        # Find start/end indices for above-threshold segments
        in_segment = False
        seg_start: Optional[pd.Timestamp] = None
        for ts, is_above in above.items():
            if is_above and not in_segment:
                in_segment = True
                seg_start = ts
            elif not is_above and in_segment:
                in_segment = False
                seg_end = ts
                # Summarize this segment
                summaries.append(
                    _summarize_interval(df_all, df_suspicious, seg_start, seg_end, float(density.loc[seg_start:seg_end].max()))
                )
        # Close open segment
        if in_segment and seg_start is not None:
            seg_end = above.index.max()
            summaries.append(
                _summarize_interval(df_all, df_suspicious, seg_start, seg_end, float(density.loc[seg_start:seg_end].max()))
            )

    return summaries


def _summarize_interval(
    df_all: pd.DataFrame,
    df_suspicious: pd.DataFrame,
    start: pd.Timestamp,
    end: pd.Timestamp,
    confidence: float,
) -> TimeframeSummary:
    mask_susp = (df_suspicious["eventTime"] >= start) & (df_suspicious["eventTime"] <= end)
    susp = df_suspicious[mask_susp]

    # Build identities tuples
    identities: List[Tuple[str, str, str, str]] = []
    for _, row in susp.iterrows():
        ip = _safe_str(row.get("sourceIPAddress"))
        ui = row.get("userIdentity") or {}
        iam = ""
        if isinstance(ui, dict):
            iam = _safe_str(ui.get("arn") or ui.get("userName") or ui.get("principalId"))
        else:
            iam = _safe_str(ui)
        ua = _safe_str(row.get("userAgent"))
        os_guess = _guess_os_from_user_agent(ua)
        identities.append((ip, iam, ua, os_guess))

    example_apis = sorted(set(_safe_str(x) for x in susp.get("eventName", [])))

    return TimeframeSummary(
        start=start,
        end=end,
        confidence=float(confidence),
        identities=identities,
        example_apis=example_apis,
    )


# ----------------------------- Run Pipeline ---------------------------


def run_pipeline(
    logs_dir: str,
    eps: float = 1.5,
    min_samples: int = 20,
) -> int:
    df = load_cloudtrail_dir(logs_dir)
    if df.empty:
        print("No logs loaded.")
        return 2

    # Step 1: filter readOnly (robust to string/number values)
    if "readOnly" in df.columns:
        s = df["readOnly"]
        if s.dtype == bool:
            ro_mask = s
        else:
            ro_mask = s.astype(str).str.lower().isin(["true", "1", "t", "yes", "y"])
        df_ro = df[ro_mask].copy()
    else:
        print("Field 'readOnly' not found; continuing with all logs for prototype.")
        df_ro = df.copy()

    if df_ro.empty:
        print("No readOnly logs after filtering.")
        return 0

    # Step 2: encode
    features = encode_dataframe(df_ro)
    if features.shape[0] == 0:
        print("No features encoded.")
        return 2

    # Step 3: cluster (DBSCAN). Target is ~24 clusters based on parameters/data
    labels = cluster_dbscan(features, eps=eps, min_samples=min_samples)

    # Print cluster metadata (as requested)
    print("\n=== Cluster Metadata (after DBSCAN) ===")
    print_cluster_metadata(df_ro, labels)

    # Select top-3 suspicious clusters by error rate
    df_suspicious, chosen_labels = select_top_suspicious_clusters(df_ro, labels, top_k=3)
    print(f"\nSelected top suspicious cluster labels: {chosen_labels}")
    print(f"Suspicious logs count: {len(df_suspicious)} out of {len(df_ro)} readOnly logs")

    # Stage 2: timeframe analysis over readOnly logs
    timeframes = analyze_timeframes(df_all=df_ro, df_suspicious=df_suspicious)

    if timeframes:
        print("\n=== Suspicious Timeframes ===")
        print(f"Count: {len(timeframes)}")
        for tf in timeframes:
            print(
                f"Timeframe {tf.start} -> {tf.end} | confidence={tf.confidence:.2%} | exampleAPIs={tf.example_apis[:10]}"
            )
            # Print a few identities for context
            if tf.identities:
                sample = tf.identities[:5]
                print(f"  identities(sample): {sample}")
    else:
        print("\nNo suspicious timeframes found with current threshold.")

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Prototype recon detection pipeline")
    parser.add_argument(
        "--logs-dir",
        required=True,
        help="Directory containing CloudTrail .json or JSON Lines files",
    )
    parser.add_argument("--eps", type=float, default=1.5, help="DBSCAN eps (after StandardScaler)")
    parser.add_argument("--min-samples", type=int, default=20, help="DBSCAN min_samples")
    args = parser.parse_args()
    return run_pipeline(args.logs_dir, eps=args.eps, min_samples=args.min_samples)


if __name__ == "__main__":
    raise SystemExit(main())


