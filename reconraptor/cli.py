from __future__ import annotations

import argparse
import json
import os
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import pandas as pd

"""
CLI options for ReconRaptor


"""

from .parser import load_cloudtrail_dir
from .detector import (
    encode_dataframe,
    cluster_dbscan_stable,
    select_top_suspicious_clusters,
    analyze_timeframes,
)
from .output import format_cluster_metadata_text, format_timeframes_table


def filter_by_time(df: pd.DataFrame, start_time: Optional[str], end_time: Optional[str]) -> pd.DataFrame:
    """Filter DataFrame by time range if specified."""
    if not start_time and not end_time:
        return df
    
    if "eventTime" not in df.columns:
        return df
    
    df = df.copy()
    if start_time:
        start_dt = pd.to_datetime(start_time)
        df = df[df["eventTime"] >= start_dt]
    if end_time:
        end_dt = pd.to_datetime(end_time)
        df = df[df["eventTime"] <= end_dt]
    
    return df


def filter_by_api_types(df: pd.DataFrame, api_types: Optional[List[str]]) -> pd.DataFrame:
    """Filter DataFrame by API types if specified."""
    if not api_types:
        return df
    
    if "eventSource" not in df.columns:
        return df
    
    # Extract service names from eventSource (e.g., "ec2.amazonaws.com" -> "ec2")
    df = df.copy()
    df["service"] = df["eventSource"].str.replace(".amazonaws.com", "", regex=False)
    mask = df["service"].isin(api_types)
    return df[mask].drop(columns=["service"])


def _format_output(data: dict, output_format: str, section_name: str, verbose: bool = False) -> None:
    """Helper function to format and print output in the specified format."""
    
    # Define output formatters for each section and format
    formatters = {
        "table": {
            "clusters": _output_clusters_table,
            "suspicious": _output_suspicious_table,
            "timeframes": _output_timeframes_table
        },
        "json": {
            "clusters": _output_clusters_json,
            "suspicious": _output_suspicious_json,
            "timeframes": _output_timeframes_json
        }
    }
    
    # Skip clusters section if not verbose
    if section_name == "clusters" and not verbose:
        return
    
    # Execute the appropriate formatter
    if output_format in formatters and section_name in formatters[output_format]:
        formatters[output_format][section_name](data)
    else:
        print(f"Unknown output format '{output_format}' or section '{section_name}'")


def _output_clusters_table(data: dict) -> None:
    """Helper function to output clusters in table format."""
    print()
    print("==========================================Clusters Metadata==========================================")
    print()
    print(format_cluster_metadata_text(data["df"], data["labels"]))


def _output_suspicious_table(data: dict) -> None:
    """Helper function to output suspicious clusters in table format."""
    print()
    print(f"Selected Top Suspicious Cluster Labels: {', '.join(map(str, data['chosen_labels']))}")
    print(f"Suspicious Logs Count: {data['suspicious_count']:,} out of {data['total_readonly']:,} readOnly logs")
    print(f"Suspicious Ratio: {(data['suspicious_count'] / data['total_readonly'] * 100):.1f}%")
    print()


def _output_timeframes_table(data: dict) -> None:
    """Helper function to output timeframes in table format."""
    print()
    print(format_timeframes_table(data["timeframes"]))


def _output_clusters_json(data: dict) -> None:
    """Helper function to output clusters in JSON format."""
    clusters = []
    df_clustered = data["df"].copy()
    df_clustered["cluster"] = data["labels"]
    
    for cluster_id in sorted(set(data["labels"])):
        if cluster_id == -1:
            continue
        cluster_data = df_clustered[df_clustered["cluster"] == cluster_id]
        clusters.append({
            "cluster_id": int(cluster_id),
            "size": len(cluster_data),
            "error_rate": float(cluster_data["errorCode"].notna().mean()),
            "event_names": sorted(set(str(x) for x in cluster_data.get("eventName", [])))
        })
    
    print(json.dumps({"clusters": clusters}, indent=2))


def _output_suspicious_json(data: dict) -> None:
    """Helper function to output suspicious clusters in JSON format."""
    print(json.dumps({
        "suspicious_clusters": data["chosen_labels"],
        "suspicious_count": data["suspicious_count"],
        "total_readonly": data["total_readonly"]
    }, indent=2))


def _output_timeframes_json(timeframes) -> None:
    """Helper function to output timeframes in JSON format."""
    tf_data = []
    for tf in timeframes:
        tf_data.append({
            "start": tf.start.isoformat(),
            "end": tf.end.isoformat(),
            "confidence": tf.confidence,
            "identities": tf.identities,
            "example_apis": tf.example_apis
        })
    
    print(json.dumps({"suspicious_timeframes": tf_data}, indent=2))


def _filter_readonly_logs(df: pd.DataFrame, verbose: bool = False) -> pd.DataFrame:
    """Helper function to filter logs by readOnly field."""
    if "readOnly" not in df.columns:
        if verbose:
            print("Field 'readOnly' not found; continuing with all logs.")
        return df.copy()
    
    s = df["readOnly"]
    if s.dtype == bool:
        ro_mask = s
    else:
        ro_mask = s.astype(str).str.lower().isin(["true", "1", "t", "yes", "y"])
    
    return df[ro_mask].copy()


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
                if verbose:
                    print(f"Warning: Unexpected data format in {file_path}")
                return []
        except Exception as e:
            if verbose:
                print(f"Warning: Could not parse {file_path}: {e}")
            return []
    else:
        # Directory - use existing parser
        df = load_cloudtrail_dir(file_path)
        if not df.empty:
            return df.to_dict(orient="records")
        return []

"""
Main function to run the analysis, will probably move to main.py

"""
def run(
    files: List[str],
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    api_types: Optional[List[str]] = None,
    output_format: str = "table",
    verbose: bool = False,
) -> int:
    # Load and combine all specified files
    all_records = []
    for file_path in files:
        records = _load_file_records(file_path, verbose)
        all_records.extend(records)
    
    if not all_records:
        print("No logs loaded from specified files.")
        return 2
    
    df = pd.DataFrame.from_records(all_records)
    
    # Ensure eventTime is parsed as datetime if present
    if "eventTime" in df.columns:
        df["eventTime"] = pd.to_datetime(df["eventTime"], errors="coerce")
    
    if verbose:
        print(f"Loaded {len(df)} total records")
    
    # Apply filters
    df = filter_by_time(df, start_time, end_time)
    df = filter_by_api_types(df, api_types)
    
    if verbose:
        print(f"After filtering: {len(df)} records")
    
    if df.empty:
        print("No logs remaining after filtering.")
        return 0

    # Filter readOnly
    df_ro = _filter_readonly_logs(df, verbose)

    if df_ro.empty:
        print("No readOnly logs after filtering.")
        return 0

    if verbose:
        print(f"Read-only logs: {len(df_ro)}")

    features = encode_dataframe(df_ro)
    if features.shape[0] == 0:
        print("No features encoded.")
        return 2

    labels = cluster_dbscan_stable(features)
    
    # Output cluster metadata (only when verbose)
    _format_output({"df": df_ro, "labels": labels}, output_format, "clusters", verbose)

    df_suspicious, chosen_labels = select_top_suspicious_clusters(df_ro, labels, top_k=3)
    
    # Output suspicious cluster information
    _format_output({
        "chosen_labels": chosen_labels,
        "suspicious_count": len(df_suspicious),
        "total_readonly": len(df_ro)
    }, output_format, "suspicious", verbose)

    timeframes = analyze_timeframes(df_all=df_ro, df_suspicious=df_suspicious)
    
    # Output timeframe analysis
    _format_output({"timeframes": timeframes}, output_format, "timeframes", verbose)
    
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="ReconRaptor - AWS CloudTrail reconnaissance detection")
    parser.add_argument(
        "-f", "--files",
        required=True,
        nargs="+",
        help="CloudTrail JSON files or directories to analyze",
    )
    parser.add_argument(
        "--start",
        help="Start time for analysis (ISO 8601 format, e.g., 2025-01-01T00:00:00Z)",
    )
    parser.add_argument(
        "--end",
        help="End time for analysis (ISO 8601 format, e.g., 2025-01-01T23:59:59Z)",
    )
    parser.add_argument(
        "--api",
        help="Comma-separated list of AWS API types to scan for (e.g., ec2,iam,s3)",
    )
    parser.add_argument(
        "--output",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable detailed logging",
    )
    
    args = parser.parse_args()
    
    # Parse API types if specified
    api_types = None
    if args.api:
        api_types = [api.strip() for api in args.api.split(",")]
    
    return run(
        files=args.files,
        start_time=args.start,
        end_time=args.end,
        api_types=api_types,
        output_format=args.output,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    raise SystemExit(main())
