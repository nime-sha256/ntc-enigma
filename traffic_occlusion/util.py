import os
import logging
from tqdm import tqdm
from scapy.all import wrpcap
import subprocess

def setup_logging(log_file="occlusion.log"):
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s"
    )

def mirror_directory_structure(source_dir, dest_dir):
    """
    Create destination directories mirroring the source directory structure.
    """
    for root, dirs, files in os.walk(source_dir):
        rel_path = os.path.relpath(root, source_dir)
        dest_path = os.path.join(dest_dir, rel_path)
        os.makedirs(dest_path, exist_ok=True)

def get_pcap_files(source_dir):
    """
    Recursively retrieve all .pcap files from the source directory.
    """
    pcap_files = []
    for root, dirs, files in os.walk(source_dir):
        for file in files:
            if file.endswith(".pcap"):
                pcap_files.append(os.path.join(root, file))
    return pcap_files

def save_packets(packets, dest_file):
    """
    Save the list of packets to a pcap file.
    """
    try:
        wrpcap(dest_file, packets)
    except Exception as e:
        logging.error(f"Error saving {dest_file}: {e}")

def get_relative_dest_path(source_file, source_dir, dest_dir):
    """
    Given a source file, compute its destination path by mirroring the directory structure.
    Replace the .pcap extension with _occluded.pcap.
    """
    rel_path = os.path.relpath(source_file, source_dir)
    base, ext = os.path.splitext(rel_path)
    new_name = base + "_occluded.pcap"
    return os.path.join(dest_dir, new_name)

def get_sni(source_file):
    try:
        command = [
            'tshark',
            '-r', source_file,
            '-Y', "tls.handshake.type == 1",
            '-T', 'fields',
            '-e', 'tls.handshake.extensions_server_name',
        ]

        sni = subprocess.check_output(command, text=True).strip()
        return sni
    except Exception as e:
        logging.error(f"Error extracting SNI {source_file}: {e}")