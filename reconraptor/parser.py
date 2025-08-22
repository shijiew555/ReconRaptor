from __future__ import annotations

import json
import os
from typing import Any, Dict, List

import pandas as pd


def load_cloudtrail_dir(logs_dir: str) -> pd.DataFrame:
    """Load CloudTrail logs from a directory of .json files into a Pandas dataframe

    Assumes user only pass in files that are only formatted in CloudTrail JSON with
    top-level {"Records": ...}, or a top-level list of records.
    """
    records: List[Dict[str, Any]] = []

    filenames = [
        os.path.join(logs_dir, name)
        for name in sorted(os.listdir(logs_dir))
        if name.lower().endswith(".json")
    ]
    for path in filenames:
        # Try json Lines, but only accept if chunks look like per event rows
        try:
            appended = 0
            for chunk in pd.read_json(path, lines=True, chunksize=100_000):
                if "eventName" not in chunk.columns:
                    appended = 0
                    break
                records.extend(chunk.to_dict(orient="records"))
                appended += len(chunk)
            if appended > 0:
                continue
        except ValueError:
            pass
        except Exception:
            pass

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


__all__ = ["load_cloudtrail_dir"]



