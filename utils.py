import logging
import sys
import time
import socket
from random import randint

import requests
from requests.exceptions import RequestException, Timeout as RequestsTimeout
from colorlog import ColoredFormatter

# nordvpn_switcher functions
from nordvpn_switcher import initialize_VPN, rotate_VPN, terminate_VPN

# Module-level LOGGER (sera initialisé par configure_logger)
LOGGER = None


def configure_logger(verbose=False, logfile_prefix="ADFSpray"):
    """
    Configure et retourne un logger 'ADFSpray'.
    Installe aussi le logger dans utils.LOGGER pour que les fonctions du module
    puissent utiliser LOGGER directement.
    """
    global LOGGER
    LOGGER = logging.getLogger("ADFSpray")

    # Level
    LOGGER.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Colors mapping
    log_colors = {
        'DEBUG': 'blue',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'red',
    }
    fmt = "%(log_color)s[%(asctime)s] - %(message)s%(reset)s"
    formatter = ColoredFormatter(fmt, datefmt='%d-%m-%Y %H:%M', log_colors=log_colors)

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    # Avoid duplicate handlers if configure_logger called multiple times
    if not any(isinstance(h, logging.StreamHandler) for h in LOGGER.handlers):
        LOGGER.addHandler(ch)

    # File handler (DEBUG)
    log_filename = f"{logfile_prefix}." + time.strftime('%d-%m-%Y') + '.log'
    fh = logging.FileHandler(filename=log_filename, mode='a')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    # Avoid adding duplicate file handler
    if not any(isinstance(h, logging.FileHandler) for h in LOGGER.handlers):
        LOGGER.addHandler(fh)

    LOGGER.debug("[utils] Logger initialisé (verbose=%s)" % verbose)
    return LOGGER


def get_public_ip(url="https://ifconfig.me", timeout=5, retries=2):
    """
    Récupère l'IP publique via un service externe, avec retries.
    Retourne la string IP ou None en cas d'échec.
    """
    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(url, timeout=timeout)
            if resp.status_code == 200:
                ip = resp.text.strip()
                if LOGGER:
                    LOGGER.debug(f"[VPN] get_public_ip success (attempt {attempt}): {ip}")
                return ip
            else:
                if LOGGER:
                    LOGGER.debug(f"[VPN] get_public_ip non-200 status {resp.status_code}")
        except (RequestException, socket.timeout, Exception) as e:
            if LOGGER:
                LOGGER.debug(f"[VPN] get_public_ip attempt {attempt} failed: {e}")
            time.sleep(1)
    if LOGGER:
        LOGGER.debug("[VPN] get_public_ip failed after retries")
    return None


def safe_rotate_vpn(prev_ip=None, rotate_retries=3, wait_initial=2, ip_check_timeout=5):
    """
    Tente de faire rotate_VPN() et s'assure autant que possible que l'IP publique a changé.
    Retourne la nouvelle IP (string) ou None si échec.
    """
    global LOGGER
    backoff = wait_initial
    for attempt in range(1, rotate_retries + 1):
        try:
            if LOGGER:
                LOGGER.info(f"[VPN] Rotating VPN (attempt {attempt}/{rotate_retries})...")
            rotate_VPN()
        except Exception as e:
            if LOGGER:
                LOGGER.warning(f"[VPN] rotate_VPN() raised: {e}")

        # Petit délai pour que la connexion VPN s'établisse
        time.sleep(backoff)

        new_ip = get_public_ip(timeout=ip_check_timeout, retries=1)
        if LOGGER:
            LOGGER.debug(f"[VPN] IP after rotate attempt {attempt}: {new_ip}")

        # si on a une ip et qu'elle diffère de la précédente -> OK
        if new_ip and prev_ip and new_ip != prev_ip:
            if LOGGER:
                LOGGER.info(f"[VPN] IP changed: {prev_ip} -> {new_ip}")
            return new_ip
        if new_ip and prev_ip is None:
            if LOGGER:
                LOGGER.info(f"[VPN] IP obtained: {new_ip}")
            return new_ip

        # sinon backoff et ré-essai
        backoff *= 2
        if LOGGER:
            LOGGER.debug(f"[VPN] rotate attempt failed or IP unchanged; sleeping {backoff}s before retry")
        time.sleep(1)

    # fallback : ré-init complet du VPN
    if LOGGER:
        LOGGER.warning("[VPN] rotate attempts exhausted, trying re-initialize VPN as fallback.")
    try:
        terminate_VPN()
        time.sleep(2)
        initialize_VPN(save=1, area_input=['France,Germany,Netherlands,United Kingdom'])
        time.sleep(4)
        new_ip = get_public_ip(timeout=ip_check_timeout, retries=2)
        if new_ip and prev_ip and new_ip != prev_ip:
            if LOGGER:
                LOGGER.info(f"[VPN] Re-init succeeded, new IP: {new_ip}")
            return new_ip
        if new_ip and prev_ip is None:
            return new_ip
    except Exception as e:
        if LOGGER:
            LOGGER.warning(f"[VPN] re-initialize fallback failed: {e}")

    if LOGGER:
        LOGGER.error("[VPN] Unable to obtain a new IP after retries.")
    return None
