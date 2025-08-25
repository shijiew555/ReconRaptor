from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List

import pandas as pd


def load_cloudtrail_dir(logs_dir: str) -> pd.DataFrame:
    """Load CloudTrail logs from a directory of .json files into a Pandas dataframe

    Assumes user only pass in files that are only formatted in CloudTrail JSON with
    top-level {"Records": ...}, or a top-level list of records.
    """
    # Check if directory exists
    if not os.path.exists(logs_dir):
        sys.stderr.write(f"Error: Directory not found: {logs_dir}\n")
        sys.exit(1)
    
    if not os.path.isdir(logs_dir):
        sys.stderr.write(f"Error: Path is not a directory: {logs_dir}\n")
        sys.exit(1)
    
    try:
        filenames = [
            os.path.join(logs_dir, name)
            for name in sorted(os.listdir(logs_dir))
            if name.lower().endswith(".json")
        ]
    except PermissionError as e:
        sys.stderr.write(f"Error: Permission denied accessing directory {logs_dir}: {e}\n")
        sys.exit(1)
    
    if not filenames:
        # Return empty DataFrame if no JSON files found
        sys.stderr.write(f"Error: No valid CloudTrail log files found in directory: {logs_dir}\n")
        sys.exit(1)
    
    records: List[Dict[str, Any]] = []
    
    for path in filenames:
        # Assume the file has valid JSON format (CloudTrail format)
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            
            if isinstance(data, dict) and "Records" in data:
                # Validate that records have required fields
                valid_records = [record for record in data["Records"] 
                               if isinstance(record, dict) and "eventName" in record]
                records.extend(valid_records)
            elif isinstance(data, list):
                # Validate that records have required fields
                valid_records = [record for record in data 
                               if isinstance(record, dict) and "eventName" in record]
                records.extend(valid_records)
        except json.JSONDecodeError as e:
            # Skip file if cannot be parsed
            sys.stderr.write(f"Warning: Invalid JSON in {path}: {e}\n")
        except FileNotFoundError as e:
            sys.stderr.write(f"Warning: File not found {path}: {e}\n")
        except PermissionError as e:
            sys.stderr.write(f"Warning: Permission denied reading {path}: {e}\n")
        except Exception as e:
            sys.stderr.write(f"Warning: Unexpected error reading {path}: {e}\n")

    if not records:
        sys.stderr.write(f"Error: No valid CloudTrail records found in directory: {logs_dir}\n")
        sys.exit(1)

    df = pd.DataFrame.from_records(records)

    # Ensure eventTime is parsed as datetime if present
    if "eventTime" in df.columns:
        try:
            df["eventTime"] = pd.to_datetime(df["eventTime"], errors="coerce")
        except Exception as e:
            sys.stderr.write(f"Warning: Could not parse eventTime column: {e}\n")
            sys.exit(1)

    return df


__all__ = ["load_cloudtrail_dir"]



