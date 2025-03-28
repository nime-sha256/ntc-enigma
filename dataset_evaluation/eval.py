import subprocess
import csv
import json
import argparse
import os
from tqdm import tqdm 
import logging

# Disable all Scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

eval_script_folder = "./"

# # # # # # # # Start - Utility Functions # # # # # # # #

# Initialize an empty dictionary to add ciphers and their decimal IDs
dict_cipher_id = {}

# Function to construct the mapping between decimal representations of a cypher suites and the readable formats (49195 -> TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
# Source: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml, https://testssl.sh/openssl-iana.mapping.html
def construct_cipher_id_dict():
    global dict_cipher_id
    csv_file = os.path.join(eval_script_folder, 'cipher-id.csv')

    with open(csv_file, mode='r', newline='') as file:
        reader = csv.reader(file)
        for row in reader:
            id, cipher = row[0], row[1]
            dict_cipher_id[id] = cipher

# Function to extract the bulk encryption algorithm (AES_128_GCM) from a decimal representation
# Note: The id-cipher.csv file has the id -> bulk encryption algorithm mapping
def convert_number_to_cipiher(number):
    number = str(number)
    if number in dict_cipher_id:
        return dict_cipher_id[number]
    else:
        print(f'{number} not found in Cipher-ID list')
        return 'NOT_FOUND'
    
# Function to run a command
def run_command(command):
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        return result.strip()
    
    except Exception as e:
        print(e)

# # # # # # # # End - Utility Functions # # # # # # # #


# # # # # # # # Start - PCAP Packet Related Functions # # # # # # # #

# Function to get the number of packets in a pcap file
def get_no_of_packets(pcap_file):
    command = "tshark -r " + pcap_file + " | wc -l"
    result = run_command(command)
    number_of_packets = int(result.split('\n')[-1].strip())

    return number_of_packets


# # # # # # # # End - PCAP Packet Related Functions # # # # # # # #


# # # # # # # # Start - TCP Related Functions # # # # # # # #

# Function to get unique tcp stream ids in the pcap file
def get_unique_tcp_stream_ids(pcap_file):
    command = "tshark -r " + pcap_file + " -T fields -e tcp.stream | sort | uniq"
    temp = run_command(command).split("\n")

    unique_tcp_stream_id_list = []

    for id in temp:
        if id.isdigit():
            unique_tcp_stream_id_list.append(id)

    return unique_tcp_stream_id_list
    
# Function to get the number of packets in a tcp stream
def get_no_of_packets_in_tcp_stream(pcap_file, stream_id):
    command = "tshark -r " + pcap_file + " -Y 'tcp.stream eq " + stream_id + "' | wc -l"
    result = run_command(command)
    number_of_packets = int(result.split('\n')[-1].strip())
    return number_of_packets

# Function to check if a tcp stream is encrypted and the number of packets with payloads
def check_encryption_and_payloads_of_tcp_stream(pcap_file, stream_id):
    command = "tshark -r " + pcap_file + " -Y 'tcp.stream eq " + stream_id + " and tls' | wc -l"
    result = run_command(command)

    number_of_packets = int(result.split('\n')[-1].strip())

    if number_of_packets == 0:
        return "unencrypted_unrelated", 0
    else:
        return "encrypted"

# Function to get the cipher suite used to encrypt a tcp stream
def get_cipher_suite_of_tcp_stream(pcap_file, stream_id):
    try:
        command = "tshark -r " + pcap_file + " -Y 'tcp.stream eq " + stream_id + " and ssl.handshake.type==2' -T fields -e tls.handshake.ciphersuite"
        cipher = run_command(command) 
        
        # Get the first cipher suite as it is highly unlikely to change in the middle of the stream
        if cipher:
            last_record = cipher.split("\n")[-1]
            if '[Epan WARNING]' not in last_record:
                cipher = int(last_record.strip(), 16)
                return convert_number_to_cipiher(cipher)
            
        return "unknown" # tls handshake packet has not been captured
    
    except:
        return "unknown"
    
# Function to get tcp stats
def get_tcp_stats(pcap_file):
    # Dictionary to store tcp streams
    tcp_streams = {}
    tcp_streams['streams'] = {}

    # Get unique tcp stream ids in the pcap file
    unique_tcp_stream_id_list = get_unique_tcp_stream_ids(pcap_file)

    tcp_streams['number_of_tcp_streams'] = len(unique_tcp_stream_id_list)
 
    # Iterate through tcp streams
    for stream_id in unique_tcp_stream_id_list:
        tcp_streams['streams'][stream_id] = {}

        # Check if the tcp stream is encrypted and get the number of packets with encrypted payloads
        tcp_streams['streams'][stream_id]['encryption_status'] = check_encryption_and_payloads_of_tcp_stream(pcap_file, stream_id)

        # Get the cipher suite used to encrypt the tcp stream
        tcp_streams['streams'][stream_id]['cipher'] = 'unencrypted_unrelated'
        if tcp_streams['streams'][stream_id]['encryption_status'] == "encrypted":
            tcp_streams['streams'][stream_id]['cipher'] = get_cipher_suite_of_tcp_stream(pcap_file, stream_id)
    
    return tcp_streams

# # # # # # # # End - TCP Related Functions # # # # # # # #


# # # # # # # # Start - UDP Related Functions # # # # # # # #

# Function to get unique udp stream ids in the pcap file
def get_unique_udp_stream_ids(pcap_file):
    command = "tshark -r " + pcap_file + " -Y udp -T fields -e udp.stream | sort | uniq"
    temp = run_command(command).split("\n")

    unique_udp_stream_id_list = []

    for id in temp:
        if id.isdigit():
            unique_udp_stream_id_list.append(id)
    
    return unique_udp_stream_id_list
    
# Function to get the number of packets in a udp stream
def get_no_of_packets_in_udp_stream(pcap_file, stream_id):
    command = "tshark -r " + pcap_file + " -Y 'udp.stream eq " + stream_id + "' | wc -l"
    result = run_command(command)
    number_of_packets = int(result.split('\n')[-1].strip())
    return number_of_packets

# Function to check if a udp stream is encrypted and the number of packets with payloads
def check_encryption_and_payloads_of_udp_stream(pcap_file, stream_id):
    command = "tshark -r " + pcap_file + " -Y 'udp.stream eq " + stream_id + " and tls' | wc -l"
    result = run_command(command)
    
    number_of_packets = int(result.split('\n')[-1].strip())

    if number_of_packets == 0:
        return "unencrypted_unrelated", 0
    else:
        return "encrypted"

# Function to get the cipher suite used to encrypt a udp stream
def get_cipher_suite_of_udp_stream(pcap_file, stream_id):
    try:
        command = "tshark -r " + pcap_file + " -Y 'udp.stream eq " + stream_id + " and tls.handshake.type==2' -T fields -e tls.handshake.ciphersuite"
        cipher = run_command(command) 
        
        # Get the first cipher suite as it is highly unlikely to change in the middle of the stream        
        if cipher:
            last_record = cipher.split("\n")[-1]
            if '[Epan WARNING]' not in last_record:
                cipher = int(last_record.strip(), 16)
                return convert_number_to_cipiher(cipher)
        
        return "unknown" # tls handshake packet has not been captured
    
    except:
        return "unknown"
    
# Function to get udp stats
def get_udp_stats(pcap_file):
    # Dictionary to store udp streams
    udp_streams = {}
    udp_streams['streams'] = {}

    # Get unique udp stream ids in the pcap file
    unique_udp_stream_id_list = get_unique_udp_stream_ids(pcap_file)

    udp_streams['number_of_udp_streams'] = len(unique_udp_stream_id_list)
 
    # Iterate through udp streams
    for stream_id in unique_udp_stream_id_list:
        udp_streams['streams'][stream_id] = {}

        # Check if the udp stream is encrypted and get the number of packets with encrypted payloads
        udp_streams['streams'][stream_id]['encryption_status'] = check_encryption_and_payloads_of_udp_stream(pcap_file, stream_id)

        # Get the cipher suite used to encrypt the udp stream
        udp_streams['streams'][stream_id]['cipher'] = 'unencrypted_unrelated'
        if udp_streams['streams'][stream_id]['encryption_status'] == "encrypted":
            udp_streams['streams'][stream_id]['cipher'] = get_cipher_suite_of_udp_stream(pcap_file, stream_id)
    
    return udp_streams

# # # # # # # # End - UDP Related Functions # # # # # # # #


# Function to process a pcap file
def process_pcap(pcap_file, dataset, label):
    pcap_stats = {
        'file_name' : pcap_file,
        'dataset' : dataset,
        'label' : label,

        'streams': {
            'all_tcp_streams': 0,
            'all_udp_streams': 0
        },

        'unencrypted_unrelated': {
            'tcp_streams': 0, # Only inclueds unencrypted/unrelated tcp streams
            'udp_streams': 0, # Only inclueds unencrypted/unrelated udp streams
            'total_streams': 0
        },

        'encrypted': {
            'tcp_streams': 0,
            'udp_streams': 0, 
            'total_streams': 0
        },
    }

    # Get tcp stats
    tcp_streams = get_tcp_stats(pcap_file)
    pcap_stats['streams']['all_tcp_streams'] = tcp_streams['number_of_tcp_streams']
    # Uncomment the following line to get a comprehensive view of tcp streams
    # pcap_stats['tcp_stats'] = tcp_streams

    # Get udp stats
    udp_streams = get_udp_stats(pcap_file)
    pcap_stats['streams']['all_udp_streams'] = udp_streams['number_of_udp_streams']
    # Uncomment the following line to get a comprehensive view of udp streams
    # pcap_stats['udp_stats'] = udp_streams

    for tcp_stream_id in tcp_streams['streams']:

        if tcp_streams['streams'][tcp_stream_id]['encryption_status'] == "encrypted":
            pcap_stats['encrypted']['tcp_streams'] += 1
            pcap_stats['encrypted']['total_streams'] += 1

        # Count the number of packets with payloads encrypted with each cipher suite
        if tcp_streams['streams'][tcp_stream_id]['cipher'] not in pcap_stats:
            pcap_stats[tcp_streams['streams'][tcp_stream_id]['cipher']] = {}
            pcap_stats[tcp_streams['streams'][tcp_stream_id]['cipher']]['tcp_streams'] = 0
            pcap_stats[tcp_streams['streams'][tcp_stream_id]['cipher']]['udp_streams'] = 0
            pcap_stats[tcp_streams['streams'][tcp_stream_id]['cipher']]['total_streams'] = 0

        pcap_stats[tcp_streams['streams'][tcp_stream_id]['cipher']]['tcp_streams'] += 1
        pcap_stats[tcp_streams['streams'][tcp_stream_id]['cipher']]['total_streams'] += 1
    
    for udp_stream_id in udp_streams['streams']:

        if udp_streams['streams'][udp_stream_id]['encryption_status'] == "encrypted":
            pcap_stats['encrypted']['udp_streams'] += 1
            pcap_stats['encrypted']['total_streams'] += 1

        # Count the number of packets with payloads encrypted with each cipher suite
        if udp_streams['streams'][udp_stream_id]['cipher'] not in pcap_stats:
            pcap_stats[udp_streams['streams'][udp_stream_id]['cipher']] = {}    
            pcap_stats[udp_streams['streams'][udp_stream_id]['cipher']]['tcp_streams'] = 0
            pcap_stats[udp_streams['streams'][udp_stream_id]['cipher']]['udp_streams'] = 0
            pcap_stats[udp_streams['streams'][udp_stream_id]['cipher']]['total_streams'] = 0

        pcap_stats[udp_streams['streams'][udp_stream_id]['cipher']]['udp_streams'] += 1
        pcap_stats[udp_streams['streams'][udp_stream_id]['cipher']]['total_streams'] += 1

    return pcap_stats


# Function to process a folder with pcap files
def process_pcap_folder(folder_path, dataset, label):
    json_results_file = os.path.join(eval_script_folder, label + '-analysis_results.json')

    # Check if the file exists - if a different folder of the same dataset has already been analyzed
    if os.path.exists(json_results_file):
        # If the file exists, read existing JSON data from file
        with open(json_results_file, 'r') as file:
            existing_data = json.load(file)
    else:
        # If the file doesn't exist, initialize existing data as an empty list
        existing_data = []

    files_in_folder = os.listdir(folder_path)

    already_processed_file_list = []

    for already_processed_results in existing_data:
        already_processed_file_list.append(already_processed_results['file_name'])

    with tqdm(total=len(files_in_folder), desc="Analyzing Files - "+label) as pbar:
        for file in files_in_folder:

            if file.endswith(".pcap") or file.endswith(".pcapng"):
                pcap_file = os.path.join(folder_path, file)

                if pcap_file in already_processed_file_list:
                    print(f"File {pcap_file} already processed. Skipping...")
                    pbar.update(1)
                    continue

                pcap_stats = process_pcap(pcap_file, dataset, label)

                existing_data.append(pcap_stats)

            pbar.update(1)
    
        pbar.close()
            
    with open(json_results_file, 'w') as file:
        json.dump(existing_data, file, indent=4)

    print(f"Analysis completed for folder: {folder_path}. Results saved in {json_results_file}")

if __name__ == "__main__":
    # Analize pcap files while iterating through folders
    parser = argparse.ArgumentParser(description="Process PCAP files in folders and calculate cipher representation.")
    parser.add_argument("dataset_folder", help="Path to the dataset containing PCAPs.")

    args = parser.parse_args()

    # Initialize the dictionary with ciphers and their decimal IDs using id-cipher.csv
    construct_cipher_id_dict()

    dataset_folder_path = args.dataset_folder
    dataset = os.path.basename(os.path.normpath(dataset_folder_path))

    if not dataset_folder_path.endswith('/'):
        dataset_folder_path += '/'

    for parent, directories, files in os.walk(dataset_folder_path):
        
        if files:

            label = parent.replace(dataset_folder_path, '').replace('/', '-')
            process_pcap_folder(parent, dataset, label)