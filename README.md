# Training-AI-to-Identify-Traffic-Types
Computer Networks Project done by Ioannis, Santiago and Karla

## Synthetic Packet Generator and Offline Detection Script

### Minimal Test with loopback
### Start a local HTTP server bound to loopback
```bash
python3 -m http.server 8000 --bind 127.0.0.1
```

### Start capture
```bash
sudo tshark -i lo0 -w out.pcap
```

### Example commands
```bash
sudo -E .venv/bin/python3 generator.py --iface lo0 web --dst 127.0.0.1 --dport 8000 --count 3
```
```bash
sudo -E .venv/bin/python3 generator.py --iface lo0 scan --dst 127.0.0.1 --ports 1499-1505 --rate 200
```
```bash
sudo -E .venv/bin/python3 generator.py --iface lo0 burst --dst 127.0.0.1 --dport 9999 --pps 1500 --seconds 2
```
### Normal
```bash
sudo -E python3 generator.py --iface lo0 dns --dst 127.0.0.1 --name example.com
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
