# Training-AI-to-Identify-Traffic-Types
Computer Networks Project done by Ioannis, Santiago and Karla

## Synthetic Packet Generator and Offline Detection Script
### Start capture
```bash
sudo tshark -i lo0 -w out.pcap
```

### Start a local HTTP server bound to loopback
```bash
python3 -m http.server 8000 --bind 127.0.0.1
```

### 
```bash
sudo -E .venv/bin/python3 generator.py --iface lo0 web --dst 127.0.0.1 --dport 8000 --count 3
```

### 
```bash
python3 detector.py --pcap out.pcap --csv flows.csv
```

### 
```bash
```
