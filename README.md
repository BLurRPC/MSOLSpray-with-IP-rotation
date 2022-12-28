# Password spraying O365 with IP rotation (nordvpn)
Password spraying O365 with IP rotation (nordvpn) every 15 attemps

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

### Usage

```bash
sudo python3 MSOLSpray.py -u <path/to/mail/file> -p '<pass>' --vpn -o result.txt
```
