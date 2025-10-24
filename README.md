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
1. Initialiser/créer la DB (si pas déjà faite)
```bash
sudo python3 db_admin.py --init
```

2. Lister les 20 derniers "success"
```bash
sudo python3 db_admin.py --list-success --limit 20
```

3. Lister les "fail"
```bash
sudo python3 db_admin.py --list-fail
```

4. Affiche les utilisateurs qui existent (MSOL uniquement)
```bash
sudo python3 db_admin.py --print-valid-users
```

5. Requête filtrée :
```bash
sudo python3 db_admin.py --query --subject alice@example.com --status success --limit 10
```

6. Export CSV :
```bash
sudo python3 db_admin.py --export out.csv --limit 500
```

7 Purge des événements de plus de 60 jours :
```bash
sudo python3 db_admin.py --purge 60
```