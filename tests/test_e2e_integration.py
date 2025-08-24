"""
End-to-end integration tests for ReconRaptor.

These tests validate that the tool produces correctly formatted JSON output
and covers the output.py, utils.py, and detector.py components.
"""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Any

import pytest


class TestEndToEndIntegration:
    """Test end-to-end integration of the tool's output format.
    
    This validates that the tool's output format is correct; 
    Ensures the detected timframes and identities are in the output
    Uses the existing test data in the data/ folder.
    """
    
    def test_json_output_format(self, test_data_path):
        """Test that JSON output is in the correct format."""
        # Run the tool with JSON output - use actual file paths
        cmd = [
            "python", "-m", "reconraptor.main",
            "-f", f"{test_data_path}/flaws_cloudtrail19.json",
            "--output", "json"
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            # Check that the command executed successfully
            assert result.returncode == 0, f"Command failed: {result.stderr}"
            
            # Parse the JSON output
            output_data = json.loads(result.stdout)
            
            # Validate the structure
            self._validate_json_structure(output_data)
            
        except subprocess.TimeoutExpired:
            pytest.fail("Command timed out after 5 minutes")
        except json.JSONDecodeError as e:
            pytest.fail(f"Invalid JSON output: {e}")
    
    def test_json_output_contains_required_sections(self, test_data_path):
        """Test that JSON output contains all required sections."""
        cmd = [
            "python", "-m", "reconraptor.main",
            "-f", f"{test_data_path}/flaws_cloudtrail19.json",
            "--output", "json"
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            assert result.returncode == 0, f"Command failed: {result.stderr}"
            output_data = json.loads(result.stdout)
            
            # Check for suspicious_timeframes section
            assert "suspicious_timeframes" in output_data, "Missing suspicious_timeframes section"
                
        except subprocess.TimeoutExpired:
            pytest.fail("Command timed out after 5 minutes")

    def test_timeframes_section_structure(self, test_data_path):
        """Test that suspicious_timeframes section has correct structure."""
        cmd = [
            "python", "-m", "reconraptor.main",
            "-f", f"{test_data_path}/flaws_cloudtrail19.json",
            "--output", "json"
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            assert result.returncode == 0, f"Command failed: {result.stderr}"
            output_data = json.loads(result.stdout)
            
            if "suspicious_timeframes" in output_data and output_data["suspicious_timeframes"]:
                timeframe = output_data["suspicious_timeframes"][0]
                required_fields = ["start", "end", "confidence", "identities", "example_apis"]
                
                for field in required_fields:
                    assert field in timeframe, f"Missing field in timeframe: {field}"
                
                # Validate data types
                assert isinstance(timeframe["start"], str)
                assert isinstance(timeframe["end"], str)
                assert isinstance(timeframe["confidence"], float)
                assert isinstance(timeframe["identities"], list)
                assert isinstance(timeframe["example_apis"], list)
                
        except subprocess.TimeoutExpired:
            pytest.fail("Command timed out after 5 minutes")
   
    def _validate_json_structure(self, data: Dict[str, Any]):
        """Helper method to validate JSON structure."""
        # Basic structure integration
        assert isinstance(data, dict), "Output should be a JSON object"
        
        # Check for at least one of the main sections
        main_sections = ["clusters", "suspicious_timeframes"]
        has_section = any(section in data for section in main_sections)
        assert has_section, "Output should contain at least one main section"
        
        # Validate that all values are JSON serializable types
        self._validate_json_types(data)
    
    def _validate_json_types(self, obj: Any):
        """Recursively validate that all values are JSON serializable."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                assert isinstance(key, str), f"Dictionary key must be string: {key}"
                self._validate_json_types(value)
        elif isinstance(obj, list):
            for item in obj:
                self._validate_json_types(item)
        else:
            # Check for basic JSON types
            valid_types = (str, int, float, bool, type(None))
            assert isinstance(obj, valid_types), f"Invalid JSON type: {type(obj)} for value: {obj}"
