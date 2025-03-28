
# Network Traffic Dataset Evaluation

## Overview
This directory contains a Python tool for analyzing PCAP files. It extracts statistics on protocol usage (e.g., TCP, UDP), encryption status (e.g., encrypted, unencrypted), and the distribution of bulk encryption algorithms. The extracted data is saved as JSON files for further analysis.

## Functionality
-   Recursively scans the specified dataset folder for PCAP files.
-   Analyzes TCP and UDP streams in each file, checking for encryption and extracting cipher suite information.
-   Aggregates statistics and writes them to a JSON file (named using the folder label, e.g., `label-analysis_results.json`).

## Requirements
- **Python 3.6+**
- **Scapy** – for reading pcap files.
- **tqdm** – for displaying progress bars.
- **Tshark** – must be installed and in your system’s PATH (used by util.get_sni).

### Install Python dependencies using pip:

    pip install scapy tqdm

### Install Tshark:

    sudo apt-get install tshark

## Usage
1. **Clone this repository::**
   ```bash
   git clone https://github.com/nime-sha256/ntc-enigma
   cd ntc-enigma/dataset_evaluation
   ```

2. Make sure all the required Python packages and Tshark are installed.

3. Run the script from the command line by providing the path to the dataset folder containing the dataset with PCAP files. For example:
   ```bash 
   python eval.py /path/to/dataset_folder
   ```