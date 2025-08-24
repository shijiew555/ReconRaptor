"""
Pytest configuration and fixtures for ReconRaptor tests.
"""

import json
import os
import tempfile
from pathlib import Path
from typing import List, Dict, Any

import pytest
import pandas as pd

# Add the project root to the Python path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from reconraptor.detector import TimeframeSummary


@pytest.fixture
def sample_cloudtrail_data() -> List[Dict[str, Any]]:
    """Sample CloudTrail data for testing.

    This is a sample of CloudTrail data that is used for testing.
    It contains two records with the same sourceIPAddress and userAgent.
    """
    return [
        {
            "eventTime": "2020-09-25T12:00:00Z",
            "eventName": "ListBuckets",
            "eventSource": "s3.amazonaws.com",
            "readOnly": True,
            "sourceIPAddress": "192.168.1.1",
            "userAgent": "aws-cli/2.0.0",
            "errorCode": None,
            "requestParameters": {},
            "responseElements": {},
            "userIdentity": {"type": "IAMUser", "userName": "testuser"}
        },
        {
            "eventTime": "2020-09-25T12:01:00Z",
            "eventName": "DescribeInstances",
            "eventSource": "ec2.amazonaws.com",
            "readOnly": True,
            "sourceIPAddress": "192.168.1.1",
            "userAgent": "aws-cli/2.0.0",
            "errorCode": "Client.UnauthorizedOperation",
            "requestParameters": {},
            "responseElements": {},
            "userIdentity": {"type": "IAMUser", "userName": "testuser"}
        },
        {
            "eventTime": "2020-09-25T12:02:00Z",
            "eventName": "GetUser",
            "eventSource": "iam.amazonaws.com",
            "readOnly": True,
            "sourceIPAddress": "192.168.1.1",
            "userAgent": "aws-cli/2.0.0",
            "errorCode": "AccessDenied",
            "requestParameters": {},
            "responseElements": {},
            "userIdentity": {"type": "IAMUser", "userName": "testuser"}
        }
    ]


@pytest.fixture
def sample_timeframes() -> List[TimeframeSummary]:
    """Sample timeframes for testing."""
    return [
        TimeframeSummary(
            start=pd.Timestamp("2020-09-25T12:00:00Z"),
            end=pd.Timestamp("2020-09-25T12:05:00Z"),
            confidence=0.85,
            identities=[("192.168.1.1", "testuser", "aws-cli/2.0.0", "Unknown")],
            example_apis=["ListBuckets", "DescribeInstances"]
        )
    ]


@pytest.fixture
def temp_json_file(sample_cloudtrail_data) -> str:
    """Create a temporary JSON file with sample CloudTrail data."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump({"Records": sample_cloudtrail_data}, f)
        return f.name


@pytest.fixture
def temp_dir_with_files(sample_cloudtrail_data) -> str:
    """Create a temporary directory with multiple JSON files."""
    temp_dir = tempfile.mkdtemp()
    
    # Create multiple files
    for i in range(3):
        file_path = os.path.join(temp_dir, f"test_{i}.json")
        with open(file_path, 'w') as f:
            json.dump({"Records": sample_cloudtrail_data}, f)
    
    return temp_dir


@pytest.fixture(scope="session")
def test_data_path() -> str:
    """Path to test data directory."""
    return "data"


def cleanup_temp_files(*files):
    """Clean up temporary files."""
    for file_path in files:
        if os.path.exists(file_path):
            os.unlink(file_path)


def cleanup_temp_dirs(*dirs):
    """Clean up temporary directories."""
    for dir_path in dirs:
        if os.path.exists(dir_path):
            import shutil
            shutil.rmtree(dir_path)
