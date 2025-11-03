import os
import sys
import argparse
import subprocess
import pandas as pd
import numpy as np

# Field names extracted from pcap files for IDS feature engineering
packetConditions = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "frame.len", "_ws.col.Protocol", "tcp.flags"
]

def runTshark(pcapPath, outCSV):
    """
    Runs TShark to extract packet data from a .pcap file.
    
    Args:
        pcapPath: Path to the input .pcap file
        outCSV: Path where the intermediate packet CSV will be saved
    
    Exits with error if pcap file doesn't exist.
    """
    if not os.path.exists(pcapPath):
        print(f"Error: {pcapPath} not found")
        sys.exit(1)

    # TShark command to extract specific fields from pcap
    cmd = [
        "tshark", "-r", pcapPath, "-T", "fields",
        "-e", "frame.number", "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst",
        "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "udp.srcport", "-e", "udp.dstport",
        "-e", "frame.len", "-e", "_ws.col.Protocol", "-e", "tcp.flags",
        "-E", "header=y", "-E", "separator=,", "-E", "quote=d"
    ]

    print("Running Tshark to create packet CSV")

    with open(outCSV, "w") as f:
        subprocess.check_call(cmd, stdout=f)

    print(f"Packet CSV written to {outCSV}")

def loadPackets(csvPath):
    """
    Loads the packet CSV created by TShark and prepares it for processing.
    
    Args:
        csvPath: Path to the CSV file containing packet data
    
    Returns:
        DataFrame with packets, missing values filled with 0
    """
    df = pd.read_csv(csvPath)
    df.fillna(0, inplace=True)  # Replace missing values with 0
    
    # Convert time and size fields to numeric (handles any malformed data)
    df["frame.time_epoch"] = pd.to_numeric(df["frame.time_epoch"], errors="coerce")
    df["frame.len"] = pd.to_numeric(df["frame.len"], errors="coerce")
    
    # Filter out non-IP packets (keep only rows with valid IP addresses)
    df = df[(df['ip.src'] != 0) & (df['ip.dst'] != 0)]
    
    return df

def normalizePorts(row):
    """
    Consolidates TCP and UDP ports into unified src/dst port columns.
    Since a packet is either TCP or UDP (not both), this merges the port info.
    
    Args:
        row: A DataFrame row with tcp.srcport, tcp.dstport, udp.srcport, udp.dstport
    
    Returns:
        Series with 'srcport' and 'dstport' (-1 if no port found)
    """
    srcPort = row['tcp.srcport'] if row['tcp.srcport'] != 0 else (row['udp.srcport'] if row['udp.srcport'] != 0 else -1)
    dstPort = row['tcp.dstport'] if row['tcp.dstport'] != 0 else (row['udp.dstport'] if row['udp.dstport'] != 0 else -1)
    return pd.Series({'srcport': srcPort, 'dstport': dstPort})

def buildFlowID(row):
    """
    Creates a unique identifier for each network flow.
    A flow = same src IP, dst IP, src port, dst port, and protocol.
    
    Args:
        row: DataFrame row with flow information
    
    Returns:
        String identifier for the flow (5-tuple)
    """
    return f"{row['ip.src']}-{row['ip.dst']}-{row['srcport']}-{row['dstport']}-{row['_ws.col.Protocol']}"

def parseTCPFlags(df):
    """
    Extracts individual TCP flag indicators from the tcp.flags field using bitwise operations.
    
    TCP flags indicate connection state:
    - SYN (0x0002): Connection initiation
    - ACK (0x0010): Acknowledgment
    - FIN (0x0001): Connection termination
    
    These are critical for detecting:
    - Port scans (many SYNs, no ACKs/FINs)
    - SYN floods (overwhelming SYN packets)
    - Incomplete connections
    
    Args:
        df: DataFrame with 'tcp.flags' column
    
    Returns:
        DataFrame with added binary columns: syn_flag, ack_flag, fin_flag
    """
    
    def extract_flags(flag_val):
        """Extract individual TCP flags using bitwise AND operations"""
        if pd.isna(flag_val) or flag_val == 0:
            return 0, 0, 0
        try:
            # Convert hex string to integer (handles both '0x0002' and 0x0002 formats)
            if isinstance(flag_val, str):
                flags = int(flag_val, 16)
            else:
                flags = int(flag_val)
            
            # Use bitwise AND to check each flag
            syn = 1 if (flags & 0x0002) else 0  # Bit 1: SYN
            ack = 1 if (flags & 0x0010) else 0  # Bit 4: ACK
            fin = 1 if (flags & 0x0001) else 0  # Bit 0: FIN
            return syn, ack, fin
        except (ValueError, TypeError):
            return 0, 0, 0
    
    # Apply flag extraction to create three new columns
    df[['syn_flag', 'ack_flag', 'fin_flag']] = df['tcp.flags'].apply(
        lambda x: pd.Series(extract_flags(x))
    )
    
    return df

def aggregateFlows(df):
    """
    Groups packets into flows and extracts ML features for intrusion detection.
    
    This is the core feature engineering function that creates the dataset
    the model will train on.
    
    Features extracted:
    - Packet count per flow
    - Packet size statistics (mean, std, min, max, total)
    - Inter-arrival time statistics (timing between packets)
    - TCP flag counts (SYN, ACK, FIN)
    - Flow duration and packet rate
    - SYN/ACK ratio (detects incomplete connections like port scans)
    - Unique destination ports (detects port scanning)
    - SYN-only packet percentage (detects SYN floods)
    
    Args:
        df: DataFrame with per-packet data and TCP flags parsed
    
    Returns:
        DataFrame where each row is one flow with aggregated features
    """
    # Normalize ports to handle both TCP and UDP
    df[['srcport', 'dstport']] = df.apply(normalizePorts, axis=1)
    
    # Create unique flow identifier
    df['flow_id'] = df.apply(buildFlowID, axis=1)
    
    # Sort by time to calculate inter-arrival times correctly
    df = df.sort_values('frame.time_epoch')
    
    # Calculate time between consecutive packets in each flow
    df['inter_arrival'] = df.groupby('flow_id')['frame.time_epoch'].diff()

    # Aggregate packets into flow-level features
    flows = df.groupby('flow_id').agg({
        'frame.number': 'count',                    # Total packets in flow
        'frame.len': ['mean', 'std', 'min', 'max', 'sum'],  # Packet size statistics (added min/max)
        'inter_arrival': ['mean', 'std'],           # Timing statistics
        'tcp.flags': lambda x: (x != 0).sum(),      # Count of packets with TCP flags
        'syn_flag': 'sum',                          # Total SYN packets
        'ack_flag': 'sum',                          # Total ACK packets
        'fin_flag': 'sum',                          # Total FIN packets
        'frame.time_epoch': ['min', 'max'],         # Flow start and end time
        'dstport': 'nunique'                        # Unique destination ports (port scan indicator)
    }).reset_index()

    # Flatten multi-level column names from aggregation
    flows.columns = ['_'.join(col).strip('_') for col in flows.columns.values]
    
    # Fill NaN values (e.g., std with single packet) with 0
    flows.fillna(0, inplace=True)
    
    # Calculate flow duration (in seconds)
    flows['duration'] = flows['frame.time_epoch_max'] - flows['frame.time_epoch_min']
    
    # Calculate packet rate (packets per second)
    # +0.001 prevents division by zero for instantaneous flows
    flows['pkt_rate'] = flows['frame.number_count'] / (flows['duration'] + 0.001)
    
    # SYN/ACK ratio helps detect port scans and SYN floods
    # High ratio = many SYNs without ACKs (incomplete connections)
    flows['syn_ack_ratio'] = flows['syn_flag_sum'] / (flows['ack_flag_sum'] + 1)
    
    # Percentage of SYN-only packets (strong indicator of SYN flood)
    flows['syn_only_pct'] = flows['syn_flag_sum'] / flows['frame.number_count']
    
    return flows

def labelFromFilename(filename):
    """
    Automatically labels flows based on the input pcap filename.
    
    Naming convention for the packet generator:
    - Files with "normal" in name → Normal traffic
    - Files with "malicious" in name → Malicious traffic
    
    Args:
        filename: Name of the .pcap file
    
    Returns:
        "Normal", "Malicious", or "Unknown"
    """
    if "normal" in filename.lower():
        return "Normal"
    elif "malicious" in filename.lower():
        return "Malicious"
    else:
        return "Unknown"

def main():
    """
    Main pipeline:
    1. Extract packets from pcap using TShark
    2. Load and parse TCP flags
    3. Aggregate into flows with ML features
    4. Label based on filename
    5. Append to master dataset (flows.csv)
    
    Usage:
        python dataset_creator.py normal_traffic.pcap packets_normal.csv
        python dataset_creator.py malicious_portscan.pcap packets_malicious.csv
    
    All flows are appended to 'flows.csv' for model training.
    """
    parser = argparse.ArgumentParser(description="Extract flow features from pcap files for IDS training")
    parser.add_argument("pcap", help="Path to input .pcap file (use 'normal' or 'malicious' in filename)")
    parser.add_argument("outcsv", help="Path for intermediate packet CSV")
    args = parser.parse_args()

    # Step 1: Run TShark to extract packet data
    runTshark(args.pcap, args.outcsv)
    
    # Step 2: Load packet data
    df = loadPackets(args.outcsv)
    
    # Check if any packets remain after filtering
    if len(df) == 0:
        print("Warning: No valid IP packets found in pcap file")
        return
    
    # Step 3: Parse TCP flags for malicious activity detection
    df = parseTCPFlags(df)
    
    # Step 4: Aggregate packets into flows with features
    flows = aggregateFlows(df)
    
    # Step 5: Label flows based on filename
    flows["label"] = labelFromFilename(args.pcap)
    
    # Step 6: Append to master dataset (or create if first run)
    output_file = "flows.csv"
    if os.path.exists(output_file):
        flows.to_csv(output_file, mode='a', header=False, index=False)
        print(f"✓ Appended {len(flows)} flows to {output_file}")
    else:
        flows.to_csv(output_file, index=False)
        print(f"✓ Created {output_file} with {len(flows)} flows")
    
    # Print summary statistics
    print(f"\nDataset Summary:")
    print(f"  Total flows: {len(flows)}")
    print(f"  Label: {flows['label'].iloc[0]}")
    print(f"  Features extracted: {len(flows.columns) - 2}")  # Exclude flow_id and label

if __name__ == "__main__":

    main()
