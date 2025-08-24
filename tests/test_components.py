"""
Component tests for ReconRaptor.

These tests test individual components (main.py and parser.py) for edge cases and error handling. 
"""

import json
import tempfile
import os
from pathlib import Path
from typing import List, Dict, Any

import pytest
import pandas as pd

from reconraptor.parser import load_cloudtrail_dir
from reconraptor.main import run
from .conftest import cleanup_temp_dirs


class TestParserComponent:
    """Test parser.py component for edge cases and error handling."""
    
    def test_parser_with_missing_fields(self):
        """Test parser exits program when records have missing eventName field."""
        # Create test data with missing eventName field (which parser requires)
        test_data = [
            {
                "eventTime": "2020-09-25T12:00:00Z"
                # Missing eventName field
            },
            {
                "readOnly": True
                # Missing eventName field
            },
            {
                # Completely empty record
            }
        ]
        
        # Create temporary directory with JSON file
        temp_dir = tempfile.mkdtemp()
        temp_file = os.path.join(temp_dir, "test.json")
        
        try:
            with open(temp_file, 'w') as f:
                json.dump({"Records": test_data}, f)
            
            # Should exit program when no valid records found
            with pytest.raises(SystemExit) as exc_info:
                load_cloudtrail_dir(temp_dir)
            
            # Should exit with code 1
            assert exc_info.value.code == 1
            
        finally:
            cleanup_temp_dirs(temp_dir)
    
    def test_parser_with_invalid_values(self):
        """Test parser exits program when records have missing eventName field."""
        # Create test data with missing eventName field (which parser requires)
        test_data = [
            {
                "eventTime": "invalid-date",
                "readOnly": "not-a-boolean",
                "sourceIPAddress": 12345,
                "userAgent": [],
                "errorCode": {},
                "requestParameters": "not-a-dict",
                "responseElements": "not-a-dict",
                "userIdentity": "not-a-dict"
                # Missing eventName field
            }
        ]
        
        # Create temporary directory with JSON file
        temp_dir = tempfile.mkdtemp()
        temp_file = os.path.join(temp_dir, "test.json")
        
        try:
            with open(temp_file, 'w') as f:
                json.dump({"Records": test_data}, f)
            
            # Should exit program when no valid records found
            with pytest.raises(SystemExit) as exc_info:
                load_cloudtrail_dir(temp_dir)
            
            # Should exit with code 1
            assert exc_info.value.code == 1
            
        finally:
            cleanup_temp_dirs(temp_dir)
    
    def test_parser_with_empty_logs(self):
        """Test parser exits program when no valid records are found."""
        # Test with empty records
        test_data = {"Records": []}
        
        # Create temporary directory with empty JSON file
        temp_dir = tempfile.mkdtemp()
        temp_file = os.path.join(temp_dir, "empty.json")
        
        try:
            with open(temp_file, 'w') as f:
                json.dump(test_data, f)
            
            # Should exit program when no valid records found
            with pytest.raises(SystemExit) as exc_info:
                load_cloudtrail_dir(temp_dir)
            
            # Should exit with code 1
            assert exc_info.value.code == 1
            
        finally:
            cleanup_temp_dirs(temp_dir)
    
    def test_parser_with_malformed_json(self):
        """Test parser exits program when JSON is malformed."""
        # Create temporary directory with malformed JSON file
        temp_dir = tempfile.mkdtemp()
        temp_file = os.path.join(temp_dir, "malformed.json")
        
        try:
            with open(temp_file, 'w') as f:
                f.write('{"Records": [{"eventName": "test"}')  # Missing closing brace
            
            # Should exit program when no valid records found
            with pytest.raises(SystemExit) as exc_info:
                load_cloudtrail_dir(temp_dir)
            
            # Should exit with code 1
            assert exc_info.value.code == 1
            
        finally:
            cleanup_temp_dirs(temp_dir)
    
    def test_parser_with_nonexistent_file(self):
        """Test parser exits program for nonexistent files."""
        nonexistent_path = "/nonexistent/path/file.json"
        
        # Should exit program for nonexistent directory
        with pytest.raises(SystemExit) as exc_info:
            load_cloudtrail_dir(nonexistent_path)
        
        # Should exit with code 1
        assert exc_info.value.code == 1


class TestMainComponent:
    """Test main.py component for CLI error handling."""
    
    def test_main_with_existing_test_file(self):
        """Test main.py works with the existing test.json file."""
        test_file_path = os.path.join(os.path.dirname(__file__), "test.json")
        
        # Verify the test file exists
        assert os.path.exists(test_file_path), f"Test file not found at {test_file_path}"
        
        try:
            result = run(
                files=[test_file_path],
                start_time=None,
                end_time=None,
                api_types=None,
                output_format="table",
                verbose=False
            )
            
            # Should process successfully
            assert result in [0, 2], f"Unexpected return code {result}"
            
        except Exception as e:
            pytest.fail(f"Main function crashed with test file: {e}")
    
    def test_main_with_invalid_time_formats(self):
        """Test main.py handles invalid time formats gracefully."""
        # Create a temporary valid file for testing time format handling
        temp_dir = tempfile.mkdtemp()
        temp_file = os.path.join(temp_dir, "test.json")
        
        try:
            # Create a minimal valid CloudTrail file with proper structure
            test_data = {
                "Records": [
                    {
                        "eventTime": "2020-09-25T12:00:00Z",
                        "eventName": "ListBuckets",
                        "readOnly": True,
                        "eventSource": "s3.amazonaws.com",
                        "awsRegion": "us-east-1",
                        "sourceIPAddress": "192.168.1.1",
                        "userAgent": "aws-cli/2.0.0",
                        "userIdentity": {
                            "type": "IAMUser",
                            "principalId": "test-user"
                        }
                    }
                ]
            }
            
            with open(temp_file, 'w') as f:
                json.dump(test_data, f)
            
            invalid_times = [
                "invalid-time",
                "2020-13-45T25:70:99Z",  # Invalid date/time
                "not-a-date",
                "",
                None
            ]
            
            for time_value in invalid_times:
                try:
                    result = run(
                        files=[temp_dir],
                        start_time=time_value,
                        end_time=None,
                        api_types=None,
                        output_format="table",
                        verbose=False
                    )
                    
                    # Should handle gracefully - either process successfully or return error
                    assert result in [0, 2], f"Unexpected return code {result} for time {time_value}"
                    
                except Exception as e:
                    pytest.fail(f"Main function crashed with time {time_value}: {e}")
                    
        finally:
            cleanup_temp_dirs(temp_dir)
    
    def test_main_with_invalid_output_format(self):
        """Test main.py handles invalid output formats gracefully."""
        # Create a temporary valid file for testing output format handling
        temp_dir = tempfile.mkdtemp()
        temp_file = os.path.join(temp_dir, "test.json")
        
        try:
            # Create a minimal valid CloudTrail file with proper structure
            test_data = {
                "Records": [
                    {
                        "eventTime": "2020-09-25T12:00:00Z",
                        "eventName": "ListBuckets",
                        "readOnly": True,
                        "eventSource": "s3.amazonaws.com",
                        "awsRegion": "us-east-1",
                        "sourceIPAddress": "192.168.1.1",
                        "userAgent": "aws-cli/2.0.0",
                        "userIdentity": {
                            "type": "IAMUser",
                            "principalId": "test-user"
                        }
                    }
                ]
            }
            
            with open(temp_file, 'w') as f:
                json.dump(test_data, f)
            
            invalid_formats = [
                "invalid",
                "xml",
                "yaml",
                "",
                None
            ]
            
            for output_format in invalid_formats:
                try:
                    result = run(
                        files=[temp_dir],
                        start_time=None,
                        end_time=None,
                        api_types=None,
                        output_format=output_format or "table",
                        verbose=False
                    )
                    
                    # Should handle gracefully
                    assert result in [0, 2], f"Unexpected return code {result} for format {output_format}"
                    
                except Exception as e:
                    pytest.fail(f"Main function crashed with output format {output_format}: {e}")
                    
        finally:
            cleanup_temp_dirs(temp_dir)
    
    def test_main_with_invalid_api_types(self):
        """Test main.py handles invalid API types gracefully."""
        # Create a temporary valid file for testing API type handling
        temp_dir = tempfile.mkdtemp()
        temp_file = os.path.join(temp_dir, "test.json")
        
        try:
            # Create a minimal valid CloudTrail file with proper structure
            test_data = {
                "Records": [
                    {
                        "eventTime": "2020-09-25T12:00:00Z",
                        "eventName": "ListBuckets",
                        "eventSource": "s3.amazonaws.com",
                        "readOnly": True,
                        "awsRegion": "us-east-1",
                        "sourceIPAddress": "192.168.1.1",
                        "userAgent": "aws-cli/2.0.0",
                        "userIdentity": {
                            "type": "IAMUser",
                            "principalId": "test-user"
                        }
                    }
                ]
            }
            
            with open(temp_file, 'w') as f:
                json.dump(test_data, f)
            
            invalid_api_types = [
                [""],  # Empty string
                ["invalid-api"],
                ["ec2", ""],  # Mixed valid/invalid
                [None],  # None values
            ]
            
            for api_types in invalid_api_types:
                try:
                    result = run(
                        files=[temp_dir],
                        start_time=None,
                        end_time=None,
                        api_types=api_types,
                        output_format="table",
                        verbose=False
                    )
                    
                    # Should handle gracefully
                    assert result in [0, 2], f"Unexpected return code {result} for API types {api_types}"
                    
                except Exception as e:
                    pytest.fail(f"Main function crashed with API types {api_types}: {e}")
                    
        finally:
            cleanup_temp_dirs(temp_dir)
