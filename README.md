# Local Network Exposure Checker (COMP H2702, Scenario D)

A **local-only** Python tool that checks `127.0.0.1` and a fixed list of TCP
ports, collects safe banner/HTTP evidence and writes an analyst report.
It never scans external networks.

## Requirements
- Python 3.8+ (standard library only, no `requirements.txt` needed)

## Input files
- `targets.txt` - target IPs (127.0.0.1 only)
- `ports.txt` - fixed test ports: 18080 (HTTP), 19090 (banner), 20001 (generic TCP), 20002 (expected CLOSED)
- `local_test_services.py` - supplied safe local test services

## How to run
1. Terminal 1: start the supplied services and leave it running  
   `python local_test_services.py`
2. Terminal 2: run the checker  
   `python exposure_checker.py`

Options: `--targets FILE --ports FILE --output-dir DIR --timeout SECONDS`

Non-loopback targets are rejected unless approved with `--allow-target`
(outside the project scope, do not use against networks you do not own).

## Output
Console summary plus `output/exposure_report.txt`, `.csv` and `.json`.

## Interpreting results
OPEN means a service is listening. It is not automatically a vulnerability:
check whether the service is expected, what it reveals and how it is protected.

## Limitations
TCP connect checks only; no UDP, no version fingerprinting, and a closed
result can also mean a firewall silently dropped the connection.

## Expected result with the supplied services
18080 OPEN (HTTP 200, text/plain), 19090 OPEN (banner), 20001 OPEN (banner), 20002 CLOSED -> 3 open, 1 closed.