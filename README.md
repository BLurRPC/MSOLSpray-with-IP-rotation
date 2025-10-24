# Password spraying O365/ADFS with IP rotation (NordVPN)
Password spraying O365/ADFS with IP rotation (nordvpn) every 15 attempts

## Prerequisites

* Nordvpn client (tested on debian)
* Connect to nordvpn
```bash
sudo nordvpn login
```
* Python packages
```bash
pip3 install -r requirements.txt
```
## Managed tenant
### Usage
```bash
sudo python3 MSOLSpray.py -U '<path/to/mail/file>' -s 2 -p '<pass>' --vpn
```

## ADFS
### Usage
```bash
sudo python3 ADFSpray.py -U '<path/to/mail/file>' -r 1 3 -p '<pass>' -t https://<adfs.tenant.com> adfs -v --vpn
```


## Retrieve data in local DB
1. Initialize/create the database (if not already done)
```bash
sudo python3 db_admin.py --init
```

2. List the 20 last "success"
```bash
sudo python3 db_admin.py --list-success --limit 20
```

3. List the "fail"
```bash
sudo python3 db_admin.py --list-fail
```

4. Print users that exist (MSOL only, ADFS script doesn't have this type of information **but** you can use MSOL script once on ADFS users to know if user exists or not in ADFS!)
```bash
sudo python3 db_admin.py --print-valid-users
```

5. Filtered request
```bash
sudo python3 db_admin.py --query --subject alice@example.com --status success --limit 10
```

6. CSV export
```bash
sudo python3 db_admin.py --export out.csv --limit 500
```

7 Purge events older than 60 days
```bash
sudo python3 db_admin.py --purge 60
```

# Roadmap
- Adding countries for NordVPN as an option
- Adding local DB as an option to:
    - Skip users with a known password
    - Skip users when the password tried has already been tried before
- Add an option for user:password wordlists (leaks)