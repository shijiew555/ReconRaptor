# ReconRaptor

A CLI tool that sniffs out suspicious reconnaissance activity in AWS CloudTrail logs.

The source code is organized in the `reconraptor/` folder with four main components:
- `main.py`: CLI interface and control flow
- `parser.py`: CloudTrail log file parsing
- `detector.py`: Suspicious activity detection and timeframe analysis
- `output.py`: Results formatting and output generation

## Environment Setup
Currently supports MacOS and Linux on X86 machine. We will use Miniconda3 for environment setup.

Install Miniconda3:
```bash
mkdir -p ~/miniconda3
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh -O ~/miniconda3/miniconda.sh
bash ~/miniconda3/miniconda.sh -b -u -p ~/miniconda3
rm ~/miniconda3/miniconda.sh
```


Then, run the following commands to create and activate the conda environment:

```bash
conda env create -f environment.yml
conda activate reconraptor-env
```

## Download CloudTrail Logs Data

We will be using `flaws.cloud`, a public CloudTrail logs dataset containing logs associated with various kinds of activities in an AWS system. For simplicity, we will be using the 2 most recent log files covering about 6 months of log activities.

Run `download_data.sh` will create folder `data/` containing the 2 most recent log files:

```bash
./download_data.sh
```

## Usage

ReconRaptor offers filter options for output, either by time, API type, or output format. It also allows different output formats, either as table or JSON.

```bash
# Basic usage
python -m reconraptor.main -f data/*.json

# Output results in json
python -m reconraptor.main -f data/*.json --output json

# Show clustering details
python -m reconraptor.main -f data/*.json --verbose
```

**CLI Options:**

- `-f, --files`: CloudTrail JSON files or directories to analyze (required)
- `--verbose`: Enable detailed logging (list DBSCAN clustering details for each log group )
- `--help`: Show help information

## Testing

ReconRaptor includes comprehensive testing with three main test categories. All tests use pytest and can be run individually or together. 

To run all tests:

```bash
python -m pytest tests/ -v
```


### 1. Component Tests (`test_components.py`)
---
**Coverage**: Unit tests for `main.py` and `parser.py` components, covering edge cases and error handling. Components `detector.py` and `output.py` are tested and covered through integration tests since they work as part of the complete pipeline.
```bash
# Run all component tests
python -m pytest tests/test_components.py -v
```
- **parser.py component**: Tests `parser.py` functions with missing fields, invalid values, empty logs, malformed JSON, and nonexistent files
    ```bash
    # Run parser.py component tests
    python -m pytest tests/test_components.py::TestParserComponent -v

    # Run specific parser.py component tests
    python -m pytest tests/test_components.py::TestParserComponent::test_parser_with_missing_fields -v
    python -m pytest tests/test_components.py::TestParserComponent::test_parser_with_invalid_values -v
    python -m pytest tests/test_components.py::TestParserComponent::test_parser_with_empty_logs -v
    python -m pytest tests/test_components.py::TestParserComponent::test_parser_with_malformed_json -v
    python -m pytest tests/test_components.py::TestParserComponent::test_parser_with_nonexistent_file -v
    ```

- **main.py component**: Tests `main.py` function with invalid file paths, time formats, output formats, and API types
    ```bash
    # Run main.py component tests
    python -m pytest tests/test_components.py::TestMainComponent -v

    # Run specific main.py component tests
    python -m pytest tests/test_components.py::TestMainComponent::test_main_with_existing_test_file -v
    python -m pytest tests/test_components.py::TestMainComponent::test_main_with_invalid_time_formats -v
    python -m pytest tests/test_components.py::TestMainComponent::test_main_with_invalid_output_format -v
    python -m pytest tests/test_components.py::TestMainComponent::test_main_with_invalid_api_types -v
    ```



### 2. End-to-End Integration Tests (`test_e2e_integration.py`)
---
Make sure to run `./download_data.sh` before running integration tests.

**Coverage**: Tests the complete tool end-to-end, validating output format, structure, and all component interactions
- **JSON Output Format**: Ensures JSON output is properly formatted and valid
- **Required Sections**: Validates presence of `clusters` and `suspicious_timeframes` sections
- **Data Structure**: Checks correct data types and field presence in output

**Run Integration Tests:**
```bash
# Run all integration tests
python -m pytest tests/test_e2e_integration.py -v

# Run specific integration tests
python -m pytest tests/test_e2e_integration.py::TestEndToEndIntegration::test_json_output_format -v
python -m pytest tests/test_e2e_integration.py::TestEndToEndIntegration::test_json_output_contains_required_sections -v
python -m pytest tests/test_e2e_integration.py::TestEndToEndIntegration::test_timeframes_section_structure -v
```