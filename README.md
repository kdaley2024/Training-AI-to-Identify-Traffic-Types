# Training-AI-to-Identify-Traffic-Types
Computer Networks Project done by Ioannis, Santiago and Karla

## Synthetic Packet Generator and Offline Detection Script

### Requirements

```bash
scapy
numpy
pandas
```

### Minimal Test with loopback
### Start a local HTTP server bound to loopback
```bash
python3 -m http.server 8000 --bind 127.0.0.1
```

### Start capture
```bash
tshark -i lo0 -w out.pcap
```

## Example commands

## Malicious

### UDP burst
```bash
sudo -E python3 generator.py --iface lo0 burst --dst 127.0.0.1 --dport 9999 --pps 2000 --seconds 3
```
### Abnormal large payload scripts
```bash
sudo -E python3 generator.py --iface lo0 abnsize --dst 127.0.0.1 --dport 8000 --size 1400 --count 20
```
### SYN flood
```bash
sudo -E python3 generator.py --iface en0 synflood --dst 10.0.0.5 --dport 80 --pps 500 --seconds 3
```
### SYN port scan
```bash
sudo -E python3 generator.py --iface en0 scan --dst 10.0.0.5 --ports 1-200 --rate 300
```
## Normal

### DNS(UDP)
```bash
sudo -E python3 generator.py --iface lo0 dns --dst 127.0.0.1 --name example.com
```
### Web(HTTP-like)
```bash
sudo -E python3 generator.py --iface lo0 web --dst 127.0.0.1 --dport 8000 --count 3
```


### When creating the pcap file in the venv using sudo, to allow permissions, run
### To avoid this, do not start the tshark capture with 'sudo'
```bash
sudo chown "$(whoami)":staff out.pcap
chmod 0644 out.pcap
```


### 
```bash
sudo python3 detector.py --pcap out.pcap --csv flows.csv
```

### 
```bash
```
