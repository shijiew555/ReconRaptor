from __future__ import annotations

from typing import Iterable, List, Sequence

import pandas as pd

from .detector import TimeframeSummary
"""
Output functions


"""

def format_cluster_metadata_text(df: pd.DataFrame, labels) -> str:
    lines: List[str] = []
    if getattr(labels, "size", 0) == 0:
        return "No clusters to display."
    
    df = df.copy()
    df["cluster"] = labels
    valid_labels = [lbl for lbl in sorted(df["cluster"].unique()) if lbl != -1]
    
    lines.extend([
        f"Clustering Results:",
        f"   • Discovered {len(valid_labels)} clusters (excluding noise)",
        ""
    ])
    
    total = len(df)
    noise_count = int((df["cluster"] == -1).sum())
    clustered_count = int(total - noise_count)
    
    lines.extend([
        f"Summary Statistics:",
        f"   • Total Logs: {total:,}",
        f"   • Clustered Logs: {clustered_count:,}",
        f"   • Noise Logs: {noise_count:,}",
        ""
    ])
    
    for i, lbl in enumerate(valid_labels, 1):
        sub = df[df["cluster"] == lbl]
        size = len(sub)
        if size == 0:
            continue
        
        error_rate = float(sub["errorCode"].notna().mean())
        unique_event_names = sorted(set(str(x) for x in sub.get("eventName", [])))
        
        lines.extend([
            f"CLUSTER #{i:02d} (ID: {lbl})",
            f"   ╭─ Size: {size:,} logs",
            f"   ├─ Error Rate: {error_rate:.1%}",
            f"   ├─ Event Names: {len(unique_event_names)} unique",
            ""
        ])
        
        # Group event names by service for better readability
        if unique_event_names:
            lines.append("   ├─ Sample Events:")
            event_groups = {}
            for event in unique_event_names[:20]:  # Limit to 20 for readability
                service = event.split('.')[0] if '.' in event else "Other"
                if service not in event_groups:
                    event_groups[service] = []
                event_groups[service].append(event)
            
            for service, events in event_groups.items():
                lines.append(f"   │   {service}: {', '.join(events)}")
        else:
            lines.append("   ├─ Events: None detected")
        
        lines.extend([
            "   ╰─" + "─" * 50,
            ""
        ])
    
    return "\n".join(lines)


def format_timeframes_table(timeframes: Sequence[TimeframeSummary]) -> str:
    if not timeframes:
        return "No suspicious timeframes found with current threshold."
    
    lines = [
        "=============================== SUSPICIOUS TIMEFRAMES =======================================",
        "",
        f"Total Suspicious Timeframes Detected: {len(timeframes)}",
        ""
    ]
    
    for i, tf in enumerate(timeframes, 1):
        # Format the timeframe header with a distinct title
        start_time = tf.start.strftime("%Y-%m-%d %H:%M:%S UTC")
        end_time = tf.end.strftime("%Y-%m-%d %H:%M:%S UTC")
        duration = tf.end - tf.start
        
        lines.extend([
            f"🔍 TIMEFRAME #{i:02d}",
            f"   ╭─ Period: {start_time} → {end_time}",
            f"   ├─ Duration: {duration}",
            f"   ├─ Confidence: {tf.confidence:.1%}",
            ""
        ])
        
        # Format example APIs with better readability
        if tf.example_apis:
            lines.append("   ├─ Example APIs Detected:")
            # Group APIs by service for better organization
            api_groups = {}
            for api in tf.example_apis[:15]:  # Limit to 15 for readability
                service = api.split('.')[0] if '.' in api else "Other"
                if service not in api_groups:
                    api_groups[service] = []
                api_groups[service].append(api)
            
            for service, apis in api_groups.items():
                lines.append(f"   │   {service}: {', '.join(apis)}")
        else:
            lines.append("   ├─ Example APIs: None detected")
        
        lines.append("")
        
        # Format identities with proper indentation and structure
        if tf.identities:
            lines.append("   ├─ Identities Involved:")
            sample = tf.identities[:5]  # Limit to 5 identities for readability
            
            for j, identity in enumerate(sample, 1):
                ip, iam, user_agent, os = identity
                
                # Clean up user agent for better readability
                if user_agent.startswith('[') and user_agent.endswith(']'):
                    user_agent = user_agent[1:-1]
                
                lines.extend([
                    f"   │  👤 Identity #{j}:",
                    f"   │          IP Address: {ip}",
                    f"   │          IAM Role: {iam}",
                    f"   │          User Agent: {user_agent}",
                    f"   │          Operating System: {os}"
                ])
                
                if j < len(sample):  # Add separator between identities
                    lines.append("   │")
            
            if len(tf.identities) > 5:
                lines.append(f"   │  ... and {len(tf.identities) - 5} more identities")
        else:
            lines.append("   ├─ Identities: None detected")
        
        # Add footer for this timeframe
        lines.extend([
            "   ╰─" + "─" * 50,
            ""
        ])
    
    return "\n".join(lines)


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
    import json
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
    import json
    print(json.dumps({
        "suspicious_clusters": data["chosen_labels"],
        "suspicious_count": data["suspicious_count"],
        "total_readonly": data["total_readonly"]
    }, indent=2))


def _output_timeframes_json(data: dict) -> None:
    """Helper function to output timeframes in JSON format."""
    import json
    tf_data = []
    for tf in data["timeframes"]:
        tf_data.append({
            "start": tf.start.isoformat(),
            "end": tf.end.isoformat(),
            "confidence": tf.confidence,
            "identities": tf.identities,
            "example_apis": tf.example_apis
        })
    
    print(json.dumps({"suspicious_timeframes": tf_data}, indent=2))


__all__ = [
    "format_cluster_metadata_text",
    "format_timeframes_table",
    "_format_output",
    "_output_clusters_table",
    "_output_suspicious_table",
    "_output_timeframes_table",
    "_output_clusters_json",
    "_output_suspicious_json",
    "_output_timeframes_json",
]



