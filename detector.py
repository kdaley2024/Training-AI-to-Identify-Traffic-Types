#!/usr/bin/env python3
"""
detector.py - simple offline flow extractor + rule-based classifier
Usage:
  python3 detector.py --pcap out.pcap --csv flows.csv
"""
import argparse
from collections import defaultdict
import numpy as np
import pandas as pd
from scapy.all import rdpcap, TCP, UDP, IP, IPv6

class Flow:
    __slots__ = ("first_ts","last_ts","pkts","bytes","sizes","times","syn","ack","fin","rst","to_srv","to_cli","proto","dport")
    def __init__(self, proto, dport):
        self.first_ts = None
        self.last_ts = None
        self.pkts = 0
        self.bytes = 0
        self.sizes = []
        self.times = []
        self.syn = self.ack = self.fin = self.rst = 0
        self.to_srv = 0
        self.to_cli = 0
        self.proto = proto
        self.dport = dport

    def add(self, ts, size, direction, flags=None):
        if self.first_ts is None: self.first_ts = ts
        self.last_ts = ts
        self.pkts += 1
        self.bytes += size
        self.sizes.append(size)
        self.times.append(ts)
        if direction>0:
            self.to_srv += 1
        else:
            self.to_cli += 1
        if flags:
            if 'S' in flags: self.syn += 1
            if 'A' in flags: self.ack += 1
            if 'F' in flags: self.fin += 1
            if 'R' in flags: self.rst += 1

    def features(self):
        dur = max(1e-9, (self.last_ts - self.first_ts))
        sizes = np.array(self.sizes, dtype=float) if len(self.sizes) else np.array([0.0])
        iats = np.diff(self.times) if len(self.times)>1 else np.array([dur])
        pps = self.pkts/dur
        mean_sz = float(sizes.mean()) if len(sizes) else 0.0
        syn_frac = self.syn/max(1,self.pkts)
        bidir = (self.to_srv>0 and self.to_cli>0)
        return {
            'pkts': self.pkts,
            'bytes': self.bytes,
            'dur': dur,
            'pps': pps,
            'mean_size': mean_sz,
            'std_size': float(sizes.std()) if len(sizes)>1 else 0.0,
            'min_iat': float(iats.min()) if len(iats) else dur,
            'mean_iat': float(iats.mean()) if len(iats) else dur,
            'syn': self.syn,
            'ack': self.ack,
            'fin': self.fin,
            'rst': self.rst,
            'syn_frac': syn_frac,
            'bidir': int(bidir),
            'proto': self.proto,
            'dport': self.dport,
        }

def five_tuple(pkt):
    v='4'
    if IPv6 in pkt:
        v='6'; ip = pkt[IPv6]; proto = ip.nh; src,dst = ip.src, ip.dst
    elif IP in pkt:
        ip = pkt[IP]; proto = ip.proto; src,dst = ip.src, ip.dst
    else:
        return None
    sport=dport=None
    if TCP in pkt:
        l=pkt[TCP]; sport, dport = l.sport, l.dport; proto_name='TCP'
    elif UDP in pkt:
        l=pkt[UDP]; sport, dport = l.sport, l.dport; proto_name='UDP'
    else:
        return None
    a=(src,sport); b=(dst,dport); flip=(a>b)
    if flip:
        src,dst = dst,src; sport,dport = dport,sport
    return (v,src,sport,dst,dport,proto_name), (not flip)

def build_flows(pcap_path):
    packets = rdpcap(pcap_path)
    flows = {}
    for pkt in packets:
        kv = five_tuple(pkt)
        if not kv:
            continue
        key, from_a_to_b = kv
        if key not in flows:
            flows[key] = Flow(key[-1], key[3])
        fl = flows[key]
        ts = float(pkt.time)
        size = len(bytes(pkt))
        flags = None
        if TCP in pkt:
            t = pkt[TCP]
            try:
                flags = t.sprintf("%flags%")
            except Exception:
                try:
                    flags = str(t.flags)
                except Exception:
                    flags = None
        fl.add(ts, size, 1 if from_a_to_b else -1, flags)
    return flows

def rule_label(feat: dict) -> str:
    # simple heuristics
    if feat['proto']=='UDP' and feat['dport']==53 and feat['pkts']<=4 and feat['bytes']<=1200:
        return 'Normal'
    if feat['proto']=='TCP' and feat['dport'] in (80,443) and feat['bidir'] and feat['pkts']>=3 and feat['pps']<200 and feat['syn']>=1 and feat['ack']>=1:
        return 'Normal'
    if feat['proto']=='TCP' and feat['bidir'] and feat['mean_size']>600 and feat['dur']>0.5 and feat['pkts']>10:
        return 'Normal'
    if feat['proto']=='TCP' and feat['syn']>=1 and feat['ack']==0 and feat['fin']==0 and feat['pkts']<=3 and feat['dur']<2:
        return 'Malicious'
    if feat['proto']=='TCP' and feat['syn_frac']>0.8 and feat['pps']>300:
        return 'Malicious'
    if feat['mean_size']<60 or feat['mean_size']>1200:
        return 'Malicious'
    if feat['pps']>1000:
        return 'Malicious'
    return 'Normal'

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pcap', required=True)
    ap.add_argument('--csv', required=True)
    args = ap.parse_args()

    flows = build_flows(args.pcap)
    rows = []
    for key, fl in flows.items():
        feat = fl.features()
        label = rule_label(feat)
        rows.append({
            'flow': key,
            **feat,
            'label': label
        })
    df = pd.DataFrame(rows)
    df.to_csv(args.csv, index=False)
    print(f"Wrote {len(df)} flow rows to {args.csv}")

if __name__ == '__main__':
    main()
