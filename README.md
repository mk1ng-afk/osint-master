# OSINT-Master

A passive reconnaissance tool written in Go.

## Features
- IP address lookup (geolocation, ISP, ASN)
- Username search across 6 platforms
- Subdomain enumeration via crt.sh
- Subdomain takeover risk detection

## Installation
```bash
git clone https://github.com/mk1ng-afk/osint-master
cd osint-master
go build -o osintmaster ./cmd/
```

## Usage
```bash
./osintmaster -i 8.8.8.8 -o result.txt
./osintmaster -u johndoe -o result.txt
./osintmaster -d example.com -o result.txt
```

## Ethical Use
This tool is for educational purposes only.
Always obtain permission before scanning targets.
