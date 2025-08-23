from __future__ import annotations

import argparse
from typing import List, Optional

import pandas as pd

"""
CLI options for ReconRaptor


"""

from .detector import (
    encode_dataframe,
    cluster_dbscan_stable,
    select_top_suspicious_clusters,
    analyze_timeframes,
    filter_by_time,
    filter_by_api_types,
    _filter_readonly_logs,
    _load_file_records,
)
from .output import (
    format_cluster_metadata_text, 
    format_timeframes_table,
    _format_output,
)


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
    
    # Output suspicious cluster information (only for table/csv output, not JSON)
    if output_format != "json":
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

