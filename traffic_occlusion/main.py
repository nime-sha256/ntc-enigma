import argparse
import logging
from tqdm import tqdm
from scapy.all import rdpcap
import occluder
import util
import pyshark

def parse_args():
    parser = argparse.ArgumentParser(description="PCAP Occlusion Script")
    parser.add_argument("source", help="Source path to the pcap dataset directory")
    parser.add_argument("destination", help="Destination path to save occluded pcap files")
    parser.add_argument("--option", choices=["D1", "D2", "C", "T", "CTD", "H1", "P1", "E1", "E2", "E3"],
                        default="CTD", help="Occlusion option (default: CTD)")
    return parser.parse_args()

def process_file(file_path, dest_file, option):
    try:
        packets = rdpcap(file_path)
    except Exception as e:
        logging.error(f"Failed to read {file_path}: {e}")
        return

    try:
        if option == "D1":
            packets = occluder.occlude_D1(packets)
        elif option == "D2":
            sni = util.get_sni(file_path)
            packets = occluder.occlude_D2(packets, sni)
        elif option == "C":
            packets = occluder.occlude_C(packets)
        elif option == "T":
            packets = occluder.occlude_T(packets)
        elif option == "CTD":
            sni = util.get_sni(file_path)
            packets = occluder.occlude_CTD(packets, sni)
        elif option == "H1":
            packets = occluder.occlude_H1(packets)
        elif option == "P1":
            packets = occluder.occlude_P1(packets)
        elif option == "E1":
            packets_pyshark = pyshark.FileCapture(file_path)
            packets = occluder.occlude_E1(packets, packets_pyshark)
        elif option == "E2":
            packets_pyshark = pyshark.FileCapture(file_path)
            packets = occluder.occlude_E2(packets, packets_pyshark)
        elif option == "E3":
            packets_pyshark = pyshark.FileCapture(file_path)
            packets = occluder.occlude_E3(packets, packets_pyshark)
        else:
            logging.error(f"Unknown occlusion option: {option}")
            return
    except Exception as e:
        logging.error(f"Error processing {file_path} with option {option}: {e}")
        return

    try:
        util.save_packets(packets, dest_file)
        logging.info(f"Processed {file_path} -> {dest_file}")
    except Exception as e:
        logging.error(f"Error saving file {dest_file}: {e}")

def main():
    args = parse_args()
    util.setup_logging()
    source_dir = args.source
    dest_dir = args.destination
    option = args.option

    # Mirror the directory structure from source to destination
    util.mirror_directory_structure(source_dir, dest_dir)
    pcap_files = util.get_pcap_files(source_dir)

    for file_path in tqdm(pcap_files, desc="Processing pcap files"):
        dest_file = util.get_relative_dest_path(file_path, source_dir, dest_dir)
        process_file(file_path, dest_file, option)

if __name__ == "__main__":
    main()
