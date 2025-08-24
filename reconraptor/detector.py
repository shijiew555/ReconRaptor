from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from typing import List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

from .parser import load_cloudtrail_dir
from .utils import (
    safe_str,
    hash32,
    ip_to_int,
    user_agent_to_num,
    json_length,
    num_keys,
    guess_os_from_user_agent,
)


@dataclass
class TimeframeSummary:
    start: pd.Timestamp
    end: pd.Timestamp
    confidence: float
    identities: List[Tuple[str, str, str, str]]  # (ip, iam, user-agent, os)
    example_apis: List[str]



def encode_row_to_vector(row: pd.Series) -> np.ndarray:
    """Encode a single CloudTrail record to a 13-dimensional vector."""
    event_name = hash32(safe_str(row.get("eventName")))
    event_source = hash32(safe_str(row.get("eventSource")))
    event_category = hash32(safe_str(row.get("eventCategory")))
    event_type = hash32(safe_str(row.get("eventType")))

    user_identity = row.get("userIdentity") or {}
    ui_type = safe_str(user_identity.get("type")) if isinstance(user_identity, dict) else safe_str(user_identity)
    user_identity_enc = hash32(ui_type)

    session_ctx = row.get("sessionContext") or {}
    sess_issuer_type = ""
    if isinstance(session_ctx, dict):
        issuer = session_ctx.get("sessionIssuer")
        if isinstance(issuer, dict):
            sess_issuer_type = safe_str(issuer.get("type"))
    session_context_enc = hash32(sess_issuer_type)

    recipient_acct = hash32(safe_str(row.get("recipientAccountId")))
    source_ip = ip_to_int(row.get("sourceIPAddress"))
    aws_region = hash32(safe_str(row.get("awsRegion")))
    user_agent_num = user_agent_to_num(row.get("userAgent"))
    error_code_present = 1 if safe_str(row.get("errorCode")) else 0
    request_param_count = num_keys(row.get("requestParameters"))
    response_len = json_length(row.get("responseElements"))

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
    if df.empty:
        return np.empty((0, 13), dtype=np.float64)
    vectors = [encode_row_to_vector(row) for _, row in df.iterrows()]
    return np.vstack(vectors) if vectors else np.empty((0, 13), dtype=np.float64)


def cluster_dbscan_stable(features: np.ndarray) -> np.ndarray:
    """
    Stable DBSCAN clustering with hardcoded optimal parameters.
    
    Args:
        features: Input feature array
    
    Returns:
        Cluster labels array
    """
    if features.size == 0:
        return np.empty((0,), dtype=int)
    
    # Set random seed for reproducibility
    np.random.seed(42)
    
    # Create a copy to avoid modifying original data
    features_copy = features.copy()
    
    # Sort features by first few dimensions to ensure consistent ordering
    # This helps DBSCAN produce more stable results
    if len(features_copy) > 1:
        # Sort by first 3 features to ensure consistent ordering
        sort_indices = np.lexsort([features_copy[:, i] for i in range(min(3, features_copy.shape[1]))])
        features_copy = features_copy[sort_indices]
    
    # Apply feature scaling
    scaler = StandardScaler()
    scaled = scaler.fit_transform(features_copy)
    
    # Configure DBSCAN with hardcoded stable parameters
    model = DBSCAN(
        eps=1.5,           # So far the most stable value for 13-dimensional clustering,
        min_samples=20,      # so that results won't change from run to run
        n_jobs=1,            # Use only single thread for stable results
        algorithm='ball_tree',  # Use ball tree also to ensure stablity across runs
        metric='euclidean'
    )
    
    # Fit and predict
    labels = model.fit_predict(scaled)
    
    # If we sorted the features, we need to restore the original order
    if len(features_copy) > 1:
        # Create a mapping back to original order
        original_indices = np.argsort(sort_indices)
        labels = labels[original_indices]
    
    return labels


def select_top_suspicious_clusters(df: pd.DataFrame, labels: np.ndarray, top_k: int = 3):
    df = df.copy()
    df["cluster"] = labels
    cluster_stats: List[Tuple[int, float, int]] = []  # (label, error_rate, size)
    for lbl, sub in df[df["cluster"] != -1].groupby("cluster"):
        size = len(sub)
        if size == 0:
            continue
        error_rate = float(sub["errorCode"].notna().mean())
        cluster_stats.append((int(lbl), error_rate, size))

    cluster_stats.sort(key=lambda x: (x[1], x[2]), reverse=True)
    chosen_labels = [lbl for lbl, _, _ in cluster_stats[:top_k]]
    suspicious_df = df[df["cluster"].isin(chosen_labels)].copy()
    return suspicious_df, chosen_labels


def print_cluster_metadata(df: pd.DataFrame, labels: np.ndarray, limit_event_names: int = 25) -> None:
    if labels.size == 0:
        sys.stderr.write("No clusters to display.\n")
        return
    df = df.copy()
    df["cluster"] = labels
    valid_labels = [lbl for lbl in sorted(df["cluster"].unique()) if lbl != -1]
    sys.stderr.write(f"Discovered {len(valid_labels)} clusters (excluding noise).\n")
    total = len(df)
    noise_count = int((df["cluster"] == -1).sum())
    clustered_count = int(total - noise_count)
    sys.stderr.write(f"Clustered logs: {clustered_count}, Noise logs: {noise_count} (total: {total})\n")
    for lbl in valid_labels:
        sub = df[df["cluster"] == lbl]
        size = len(sub)
        if size == 0:
            continue
        error_rate = float(sub["errorCode"].notna().mean())
        unique_event_names = sorted(set(safe_str(x) for x in sub.get("eventName", [])))
        if len(unique_event_names) > limit_event_names:
            shown = unique_event_names[:limit_event_names]
            unique_event_names_str = f"{shown} ... (+{len(unique_event_names)-len(shown)} more)"
        else:
            unique_event_names_str = str(unique_event_names)
        sys.stderr.write(
            f"Cluster {lbl}: size={size}, error_rate={error_rate:.2%}, eventNames={unique_event_names_str}\n"
        )


def analyze_timeframes(
    df_all: pd.DataFrame,
    df_suspicious: pd.DataFrame,
    window_minutes: int = 60,
    density_threshold: float = 0.10,
) -> List[TimeframeSummary]:
    if df_all.empty or "eventTime" not in df_all.columns:
        return []

    all_ts = (
        df_all.dropna(subset=["eventTime"]).set_index("eventTime").sort_index()
    )
    susp_ts = (
        df_suspicious.dropna(subset=["eventTime"]).set_index("eventTime").sort_index()
    )

    total_per_min = all_ts["eventName"].resample("1min").count()
    susp_per_min = susp_ts["eventName"].resample("1min").count()
    idx = total_per_min.index.union(susp_per_min.index)
    total_per_min = total_per_min.reindex(idx, fill_value=0)
    susp_per_min = susp_per_min.reindex(idx, fill_value=0)

    window = f"{window_minutes}min"
    total_win = total_per_min.rolling(window=window, min_periods=1).sum()
    susp_win = susp_per_min.rolling(window=window, min_periods=1).sum()
    density = (susp_win / total_win).fillna(0.0)

    above = density >= density_threshold
    summaries: List[TimeframeSummary] = []
    if above.any():
        in_segment = False
        seg_start: Optional[pd.Timestamp] = None
        for ts, is_above in above.items():
            if is_above and not in_segment:
                in_segment = True
                seg_start = ts
            elif not is_above and in_segment:
                in_segment = False
                seg_end = ts
                summaries.append(
                    _summarize_interval(df_all, df_suspicious, seg_start, seg_end, float(density.loc[seg_start:seg_end].max()))
                )
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

    identities: List[Tuple[str, str, str, str]] = []
    for _, row in susp.iterrows():
        ip = safe_str(row.get("sourceIPAddress"))
        ui = row.get("userIdentity") or {}
        iam = ""
        if isinstance(ui, dict):
            iam = safe_str(ui.get("arn") or ui.get("userName") or ui.get("principalId"))
        else:
            iam = safe_str(ui)
        ua = safe_str(row.get("userAgent"))
        os_guess = guess_os_from_user_agent(ua)
        identities.append((ip, iam, ua, os_guess))

    example_apis = sorted(set(safe_str(x) for x in susp.get("eventName", [])))

    return TimeframeSummary(
        start=start,
        end=end,
        confidence=float(confidence),
        identities=identities,
        example_apis=example_apis,
    )


def filter_by_time(df: pd.DataFrame, start_time: Optional[str], end_time: Optional[str]) -> pd.DataFrame:
    """Filter DataFrame by time range if specified."""
    if not start_time and not end_time:
        return df
    
    if "eventTime" not in df.columns:
        return df
    
    # Use boolean masking instead of copying and modifying
    mask = pd.Series([True] * len(df), index=df.index)
    
    if start_time:
        try:
            start_dt = pd.to_datetime(start_time)
            mask &= df["eventTime"] >= start_dt
        except (ValueError, TypeError):
            # If time parsing fails, return original DataFrame
            sys.stderr.write(f"Warning: Could not parse start time '{start_time}'; skipping start time filter\n")
            return df
    
    if end_time:
        try:
            end_dt = pd.to_datetime(end_time)
            mask &= df["eventTime"] <= end_dt
        except (ValueError, TypeError):
            # If time parsing fails, return original DataFrame
            sys.stderr.write(f"Warning: Could not parse end time '{end_time}'; skipping end time filter\n")
            return df
    
    return df[mask]


def filter_by_api_types(df: pd.DataFrame, api_types: Optional[List[str]]) -> pd.DataFrame:
    """Filter DataFrame by API types if specified."""
    if not api_types:
        return df
    
    if "eventSource" not in df.columns:
        return df
    
    # Extract service names from eventSource (e.g., "ec2.amazonaws.com" -> "ec2")
    df = df
    df["service"] = df["eventSource"].str.replace(".amazonaws.com", "", regex=False)
    mask = df["service"].isin(api_types)
    return df[mask].drop(columns=["service"])


def filter_readonly_logs(df: pd.DataFrame, verbose: bool = False) -> pd.DataFrame:
    """Filter logs by readOnly field."""
    if "readOnly" not in df.columns:
        sys.stderr.write("Field 'readOnly' not found; continuing with all logs.\n")
        return df
    
    s = df["readOnly"]
    if s.dtype == bool:
        ro_mask = s
    else:
        ro_mask = s.astype(str).str.lower().isin(["true", "1", "t", "yes", "y"])
    
    return df[ro_mask].copy()


def _filter_readonly_logs(df: pd.DataFrame, verbose: bool = False) -> pd.DataFrame:
    """Helper function to filter logs by readOnly field (alias for filter_readonly_logs)."""
    return filter_readonly_logs(df, verbose)


def _load_file_records(file_path: str, verbose: bool = False) -> List[dict]:
    """Helper function to load records from a single file or directory."""
    
    if os.path.isfile(file_path):
        # Single file - treat as CloudTrail JSON
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict) and "Records" in data:
                return data["Records"]
            elif isinstance(data, list):
                return data
            else:
                sys.stderr.write(f"Warning: Unexpected data format in {file_path}\n")
                return []
        except Exception as e:
            sys.stderr.write(f"Warning: Could not parse {file_path}: {e}\n")
            return []
    elif os.path.isdir(file_path):
        # Directory - use existing parser
        try:
            df = load_cloudtrail_dir(file_path)
            if not df.empty:
                return df.to_dict(orient="records")
            else:
                sys.stderr.write(f"Warning: No valid JSON files found in directory: {file_path}\n")
                return []
        except (FileNotFoundError, NotADirectoryError, PermissionError) as e:
            sys.stderr.write(f"Warning: Could not access directory {file_path}: {e}\n")
            return []
        except Exception as e:
            sys.stderr.write(f"Warning: Unexpected error processing directory {file_path}: {e}\n")
            return []
    else:
        # Path doesn't exist
        sys.stderr.write(f"Warning: Path does not exist: {file_path}\n")
        return []


__all__ = [
    "encode_row_to_vector",
    "encode_dataframe",
    "cluster_dbscan_stable",
    "select_top_suspicious_clusters",
    "print_cluster_metadata",
    "analyze_timeframes",
    "TimeframeSummary",
    "filter_by_time",
    "filter_by_api_types",
    "filter_readonly_logs",
    "_filter_readonly_logs",
    "_load_file_records",
]



