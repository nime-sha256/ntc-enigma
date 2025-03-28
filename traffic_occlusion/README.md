# PCAP Occlusion Tool

  

## Overview

This directory contains a Python tool for applying various occlusion strategies to pcap files containing network traffic. The tool leverages Scapy for packet manipulation and PyShark for complementary packet inspection. It is designed to enable researchers to explore various techniques for masking sensitive information in captured network traffic.

  

## Important Notice:

> This code does not implement all occlusion combinations exactly as
> outlined in the paper. For example, the paper’s “C” occlusion involves
> randomizing IP IDs, IP checksums, TCP sequence/acknowledgment numbers,
> and Strong Identification Information (SII). However, the current
> implementation does not automatically include the randomization of SII
> within the “C” occlusion. To achieve the desired behavior, occlusions
> can be applied sequentially. For instance, running the D1 occlusion
> first (which anonymizes SII such as MAC/IP addresses and ports)
> followed by the C occlusion (which randomizes IP IDs and TCP
> sequence/acknowledgment numbers) produces results that align more
> closely with the experimental setup described in the paper.

  

## Functionality

### 1. main.py
The driver script which:
-  Parses command-line arguments.
- Recursively processes pcap files in a source directory.
- Uses PyShark when necessary (for occlusions that need TLS/QUIC information).
- Applies a selected occlusion option (D1, D2, C, T, CTD, H1, P1, E1, E2, or E3).
- Saves the occluded files to a destination directory that mirrors the source structure.

  
### 2. util.py
Contains helper functions for:
- Logs and tracks progress.
- Mirrors the source directory structure.
- Retrieves all pcap files recursively.
- Saves modified packets to pcap files.
- Extracts SNI information from pcap files using Tshark.

### 3. occluder.py
Implements the various occlusion functions:
- **D1**: Anonymizes strong identifiers (MAC/IP addresses and ports) using randomly generated values that remain constant within each file.
- **D2**: Replaces the SNI field with a randomly generated SNI (of the same length to preserve payload size).
- **C**: Adjusts IP IDs and TCP sequence/acknowledgment numbers while preserving relative differences (per session).
- **T**: Randomizes TCP window sizes and TCP options (including timestamps) on a per-flow basis.
- **CTD**: Sequentially applies D1, D2, T, and C occlusions (acts as an example to run occlusions sequentially).
- **H1**: Removes payload, leaving only Ethernet, IP, and TCP/UDP header fields.
- **P1**: Zeros out header-related fields while retaining the original payload.
- **E1, E2, E3**: Variants for masking payload information:
	- **E1**: Masks any plaintext (header and unencrypted payload) with 0x00 while leaving the encrypted payload unchanged.
	- **E2**: Masks the encrypted payload with 0xFF.
	- **E3**: Replaces the encrypted payload with random hexadecimal bytes.

  
## Requirements
- **Python 3.6+**
- **Scapy** – for reading and manipulating pcap files.
- **PyShark** – for detailed packet inspection (used in occlusions E1–E3).
- **tqdm** – for displaying progress bars.
- **Tshark** – must be installed and in your system’s PATH (used by util.get_sni).

### Install Python dependencies using pip:

    pip install scapy pyshark tqdm

### Install Tshark:

    sudo apt-get install tshark

## Usage

1. **Clone this repository::**
	```bash
	    git clone https://github.com/yourusername/pcap-occlusion-tool.git
	    cd ntc-enigma/traffic_occlusion
	```

2. Make sure all the required Python packages and Tshark are installed.

3. Run the tool with the following command:

	    python main.py /path/to/source_dir /path/to/dest_dir --option OPTION

	Where.
	* **/path/to/source_dir** : The source directory, which contains the original pcap files
	* **/path/to/dest_dir** : The destination directory to which the occluded pcap files are saved.
	* **OPTION**: can be one of **D1, D2, C, T, CTD, P1, H1, E1, E2, E3**

For example, to apply the occlusion (CTD), run:

    python main.py /path/to/source_dir /path/to/dest_dir --option CTD

**NOTE:**

> The code assumes that each source pcap file contains one of the four
> granularities discussed in the paper: **Packet, Burst, Flow,
> Session**. Adjustments for multi-session pcaps are not provided.
