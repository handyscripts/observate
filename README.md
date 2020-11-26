# Observate - Network Aware

Quickly visualise a single NMAP XML scan.

__Create network graphs easily, and quickly see which hosts have the biggest attack surface.__
![Network Scan Graph](/media/graph.png)

__View the scanned devices, their open ports and potential Operating System matches.__
![Network Devices List](/media/list.png)

__To create XML output from an nmap scan with OS detection:__
```
nmap -oX out.xml -O <hosts>
```

## Quick Start
```
docker run -d --name observate -p 80:80 handyscripts/observate
```

## Docker Build and Deploy

```
docker build -t observate .
docker run -d --name observate -p 80:80 observate
```

## Development 

```
cd app
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
python main.py
```

## Future goals:
* Find the difference between two scans
* Continuously search for changes in your network over time.
* Allow for upload of PCAP files
* Build a network profile with a combination of scans and scan types
* Include support for traceroute network hops in NMAP