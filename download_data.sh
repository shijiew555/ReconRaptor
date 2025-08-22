#!/bin/bash
mkdir -p data && cd data && rm -r *

# Download log data tar file
curl -L -o flaws_cloudtrail_logs.tar https://summitroute.com/downloads/flaws_cloudtrail_logs.tar
tar -xvf flaws_cloudtrail_logs.tar

# Move and unzip the last 2 log files into data/
cd flaws_cloudtrail_logs && mv flaws_cloudtrail18.json.gz flaws_cloudtrail19.json.gz .. && cd ..
gunzip *.gz

rm -rf *.tar flaws_cloudtrail_logs
cd ..
