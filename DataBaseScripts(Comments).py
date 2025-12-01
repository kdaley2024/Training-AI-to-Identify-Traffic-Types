import os
import sys
import argparse
import subprocess
import pandas as pd
import numpy as np

packetConditions = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "frame.len", "frame.protocols", "tcp.flags"
]

def runTshark(pcapPath, outCSV):
    """ Runs TShark to extract CSV packet data """
    if not os.path.exists(pcapPath):
        print(f"Error: {pcapPath} not found")
        sys.exit(1)

    cmd = [
        "tshark", "-r", pcapPath, "-T", "fields",
        "-e", "frame.number", "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst",
        "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "udp.srcport", "-e", "udp.dstport",
        "-e", "frame.len", "-e", "frame.protocols", "-e", "tcp.flags",
        "-E", "header=y", "-E", "separator=,", "-E", "quote=d"
    ]

    print(f"Running Tshark on {pcapPath}")

    with open(outCSV, "w") as f:
        subprocess.check_call(cmd, stdout=f)

def loadPackets(csvPath):
    df = pd.read_csv(csvPath)
    df.fillna(0, inplace=True)
    df["frame.time_epoch"] = pd.to_numeric(df["frame.time_epoch"], errors="coerce")
    df["frame.len"] = pd.to_numeric(df["frame.len"], errors="coerce")
    df = df[(df['ip.src'] != 0) & (df['ip.dst'] != 0)]
    return df

def normalizePorts(row):
    srcPort = row['tcp.srcport'] if row['tcp.srcport'] != 0 else (row['udp.srcport'] if row['udp.srcport'] != 0 else -1)
    dstPort = row['tcp.dstport'] if row['tcp.dstport'] != 0 else (row['udp.dstport'] if row['udp.dstport'] != 0 else -1)
    return pd.Series({'srcport': srcPort, 'dstport': dstPort})

def buildFlowID(row):
    return f"{row['ip.src']}-{row['ip.dst']}-{row['srcport']}-{row['dstport']}-{row['frame.protocols']}"

def parseTCPFlags(df):
    def extract_flags(flag_val):
        if pd.isna(flag_val) or flag_val == 0:
            return 0, 0, 0
        try:
            flags = int(flag_val, 16) if isinstance(flag_val, str) else int(flag_val)
            syn = 1 if (flags & 0x0002) else 0
            ack = 1 if (flags & 0x0010) else 0
            fin = 1 if (flags & 0x0001) else 0
            return syn, ack, fin
        except:
            return 0, 0, 0

    df[['syn_flag', 'ack_flag', 'fin_flag']] = df['tcp.flags'].apply(
        lambda x: pd.Series(extract_flags(x))
    )
    return df

def aggregateFlows(df):
    df[['srcport', 'dstport']] = df.apply(normalizePorts, axis=1)
    df['flow_id'] = df.apply(buildFlowID, axis=1)
    df = df.sort_values('frame.time_epoch')
    df['inter_arrival'] = df.groupby('flow_id')['frame.time_epoch'].diff()

    flows = df.groupby('flow_id').agg({
        'frame.number': 'count',
        'frame.len': ['mean', 'std', 'min', 'max', 'sum'],
        'inter_arrival': ['mean', 'std'],
        'tcp.flags': lambda x: (x != 0).sum(),
        'syn_flag': 'sum',
        'ack_flag': 'sum',
        'fin_flag': 'sum',
        'frame.time_epoch': ['min', 'max'],
        'dstport': 'nunique'
    }).reset_index()

    flows.columns = ['_'.join(col).strip('_') for col in flows.columns.values]
    flows.fillna(0, inplace=True)

    flows['duration'] = flows['frame.time_epoch_max'] - flows['frame.time_epoch_min']
    flows['pkt_rate'] = flows['frame.number_count'] / (flows['duration'] + 0.001)
    flows['syn_ack_ratio'] = flows['syn_flag_sum'] / (flows['ack_flag_sum'] + 1)
    flows['syn_only_pct'] = flows['syn_flag_sum'] / flows['frame.number_count']

    return flows

def process_single_pcap(pcap):
    temp_csv = "temp_packets.csv"
    runTshark(pcap, temp_csv)
    df = loadPackets(temp_csv)
    
    if len(df) == 0:
        print(f"Warning: {pcap} produced no valid IP packets.")
        return pd.DataFrame()
    
    df = parseTCPFlags(df)
    flows = aggregateFlows(df)
    os.remove(temp_csv)
    return flows

def main():
    parser = argparse.ArgumentParser(description="Extract flow features from multiple .pcap files")
    parser.add_argument("pcaps", nargs="+", help="One or more pcap files")
    args = parser.parse_args()

    all_flows = []

    for pcap in args.pcaps:
        print(f"\n=== Processing {pcap} ===")
        flows = process_single_pcap(pcap)
        if not flows.empty:
            all_flows.append(flows)

    if not all_flows:
        print("No flows extracted from any pcap.")
        return

    final_df = pd.concat(all_flows, ignore_index=True)
    final_df.to_csv("flows.csv", index=False)

    print("\n=================================")
    print(f"✓ Generated flows.csv")
    print(f"✓ Total flows: {len(final_df)}")
    print("=================================")

if __name__ == "__main__":
    main()
