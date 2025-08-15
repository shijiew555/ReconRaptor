# Design Document: ReconRaptor - AWS CloudTrail Reconnaissance Detection Tool



## Introduction



### Purpose

---
This document outlines the design for a command-line tool that detects reconnaissance activity in AWS CloudTrail logs. The tool will analyze CloudTrail logs to identify suspicious scanning patterns and provide security analysts with actionable intelligence about potential reconnaissance activities.

### Scope

---
The tool will:
- Process CloudTrail logs in JSON format from one or multiple files
- Detect reconnaissance activity using predefined API signatures and optional machine learning clustering
- Output timeframes of suspicious activity with confidence scores, actor identities, and example API calls
- Support filtering by time ranges and specific API types
- Handle large log volumes efficiently using TailPipe

### Definitions, Acronyms and Abbreviations

---
- **CloudTrail**: AWS service that logs API calls and account activity
- **Reconnaissance**: Information gathering activities that may precede cyber attacks
- **TailPipe**: Go-based open source log querying tool that uses DuckDB for processing
- **DuckDB**: In-process analytical database designed for analytical workloads
- **K-means**: Clustering algorithm that partitions data into K groups based on similarities
- **LogAI**: Salesforce's open-source log analysis and intelligence platform

### References

---
- [Flaws.cloud CloudTrail Dataset](https://summitroute.com/blog/2020/10/09/public_dataset_of_cloudtrail_logs_from_flaws_cloud/)
- [TailPipe GitHub Repository](https://github.com/turbot/tailpipe)
- [LogAI Clustering Demo](https://github.com/salesforce/logai/tree/main?tab=readme-ov-file#log-clustering)
<!-- - [AWS Reconnaissance API Reference](https://github.com/shijiew555/ReconRaptor/blob/main/docs/aws_recon_api_reference.md) -->
- [AWS Reconnaissance API Reference](aws_recon_api_reference.md)

