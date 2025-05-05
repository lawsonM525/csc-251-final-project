# Port Scanner Tool

## Overview
We implement a port scanning tool that can perform various types of network scans including connect scan, SYN scan, and UDP scan.

## Team Members
- Malaz Solaiman
- Quinn He
- Michelle Lawson

## Project Files
- `port_scanner.py` - Main scanning tool
- `contribution.md` - Team contributions
- `README.md` - This documentation
- `challenges.md` - Challenges we faced

## Usage Instructions
Run the tool using the following command format:
```
python port_scanner.py [target] -mode [mode] -order [order] -ports [port_selection]
```
For example:
```
python port_scanner.py glasgow.smith.edu -mode connect -order order -ports known
```

### Parameters:
- `target`: The hostname or IP address to scan (e.g., glasgow.smith.edu)
- `-mode`: Scanning mode (connect, syn, or udp)
- `-order`: Order for port scanning
- `-ports`: Port selection (e.g., "known" for common ports)

## Examples

### Connect Scan Example
![Connect scan example](https://github.com/user-attachments/assets/d708c543-01e4-44eb-8101-f867b4c899d1)

### SYN Scan Example
![SYN scan example](https://github.com/user-attachments/assets/f2e425f1-a2de-4f35-93da-119c9f2b3b51)

### UDP Scan Example
![UDP scan example](https://github.com/user-attachments/assets/53522ed7-f078-4f82-824d-6d5686c5381a)
