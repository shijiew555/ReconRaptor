# ReconRaptor

A CLI tool that sniffs out suspicious reconnaissance activity in AWS CloudTrail logs.

## Environment Setup
Currently supports MacOS and Linux on X86 machine. We use Miniconda3 for environment setup.

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

We will be using `flaws.cloud`, a public CloudTrail logs dataset containing logs associated with various kinds of activities in an AWS system.

For simplicity, we will be using the 2 most recent log files covering about 6 months of log activities:

```bash
./download_data.sh
```

## Usage

Run the tool with CloudTrail logs:

```bash
python3 pipeline.py --logs-dir ./data
```

Run with specific DBSCAN clustering parameters:

```bash
python3 pipeline.py --logs-dir ./data --eps 1.5 --min-samples 20 
```

