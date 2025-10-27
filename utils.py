# utils.py
import logging
import sys
import time
import socket
import csv
import requests
from requests.exceptions import RequestException, Timeout as RequestsTimeout
from colorlog import ColoredFormatter
from nordvpn_switcher import initialize_VPN, rotate_VPN, terminate_VPN
from random import randint

# --- DB imports (SQLAlchemy) ---
from pathlib import Path
from typing import Optional, List, Dict, Any
from sqlalchemy import or_, create_engine, Column, Integer, String, DateTime, Text, Index
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.exc import SQLAlchemyError
import datetime

# ------------------------------
LOGGER = None

def configure_logger(verbose=False, logfile_prefix="ADFS"):
    global LOGGER
    LOGGER = logging.getLogger("logs")

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
                    LOGGER.debug(f"[IP] get_public_ip success (attempt {attempt}): {ip}")
                return ip
            else:
                if LOGGER:
                    LOGGER.debug(f"[IP] get_public_ip non-200 status {resp.status_code}")
        except (RequestException, socket.timeout, Exception) as e:
            if LOGGER:
                LOGGER.debug(f"[IP] get_public_ip attempt {attempt} failed: {e}")
            time.sleep(1)
    if LOGGER:
        LOGGER.debug("[IP] get_public_ip failed after retries")
    return None


def safe_rotate_vpn(area, prev_ip=None, rotate_retries=3, wait_initial=2, ip_check_timeout=5):
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
        # NOTE: area_input expects a list; original string left as user provided
        initialize_VPN(save=1, area_input=[area])
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


def excptn(e):
    if LOGGER:
        LOGGER.critical("[!]Exception: " + str(e))
    else:
        print("[!]Exception: " + str(e), file=sys.stderr)
    exit(1)


def _load_list_file(path: str) -> List[str]:
    """
    Helper interne.
    Lit un fichier texte ligne par ligne (UTF-8),
    strip() chaque ligne, ignore les lignes vides,
    et retourne une liste en préservant l'ordre d'origine
    sans doublons successifs.
    """
    seen = set()
    ordered = []
    with open(path, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line:
                # ignore lignes vides
                continue
            if line not in seen:
                seen.add(line)
                ordered.append(line)
    return ordered


def userlist(path: str) -> List[str]:
    """
    Retourne la liste nettoyée des utilisateurs.
    """
    return _load_list_file(path)


def passwordlist(path: str) -> List[str]:
    """
    Retourne la liste nettoyée des mots de passe.
    """
    return _load_list_file(path)


def targetlist(path: str) -> List[str]:
    """
    Retourne la liste nettoyée des cibles.
    """
    return _load_list_file(path)
    
def random_time(minimum, maximum):
    sleep_amount = randint(minimum, maximum)
    return sleep_amount

# ==========================
# Local DB (SQLite) helpers
# ==========================

# SQLAlchemy setup (lazy-init)
Base = declarative_base()
SessionLocal = None
_ENGINE = None

class Event(Base):
    __tablename__ = "events"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    subject = Column(String(255), index=True, nullable=True)   # ex: username
    password = Column(String(255), index=True, nullable=True)   # ex: password
    target = Column(String(255), index=True, nullable=True)    # ex: target URL/host
    status = Column(String(50), index=True)                    # ex: "success", "invalid", "timeout"
    ip = Column(String(50), index=True)                        # ex: "185.11.188.112"
    details = Column(Text, nullable=True)                      # JSON/text metadata
    run_id = Column(String(64), index=True, nullable=True)     # optional grouping id (execution id)

# index to speed up lookups by subject/target/status
Index("ix_events_subject_target_status", Event.subject, Event.target, Event.status)

def init_db(sqlite_path: str = "events.db", echo: bool = False):
    """
    Initialize the local SQLite DB for events.
    Call this once at program startup.
    Returns the session factory.
    """
    global _ENGINE, SessionLocal
    db_file = Path(sqlite_path)
    db_uri = f"sqlite:///{db_file.resolve()}"
    _ENGINE = create_engine(db_uri, connect_args={"check_same_thread": False}, echo=echo)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_ENGINE)
    Base.metadata.create_all(bind=_ENGINE)
    if LOGGER:
        LOGGER.debug(f"[DB] Initialized SQLite DB at {db_file.resolve()}")
    return SessionLocal

def get_session():
    if SessionLocal is None:
        raise RuntimeError("DB not initialized. Call init_db() first.")
    return SessionLocal()

def log_event(subject: str,
              password: str,
              target: Optional[str],
              status: str,
              ip: str,
              details: Optional[str] = None,
              run_id: Optional[str] = None) -> int:
    """
    Insert a single event. Returns the inserted event id.
    subject/target/password are generic strings (e.g. username, service).
    status is a short string like 'success'/'invalid'/'timeout'.
    ip is a short string like 185.11.188.112.
    details can be JSON/text with extra info.
    """
    session = get_session()
    try:
        ev = Event(subject=subject, password=password, target=target, status=status, ip=ip, details=details, run_id=run_id)
        session.add(ev)
        session.commit()
        session.refresh(ev)
        if LOGGER:
            LOGGER.debug(f"[DB] Logged event id={ev.id} subject={subject} status={status} ip={ip} target={target} details={details}")
        return ev.id
    except SQLAlchemyError as e:
        session.rollback()
        if LOGGER:
            LOGGER.error(f"[DB] Failed to log event: {e}")
        raise
    finally:
        session.close()

def get_successful_events(limit: int = 10000, newest_first: bool = True) -> List[Dict[str, Any]]:
    """
    Return events where status equals 'success' (case-insensitive).
    """
    session = get_session()
    try:
        q = session.query(Event).filter(Event.status.ilike("success"))
        q = q.order_by(Event.timestamp.desc() if newest_first else Event.timestamp.asc())
        rows = q.limit(limit).all()
        return [_row_to_dict(r) for r in rows]
    finally:
        session.close()

def get_failed_events(limit: int = 10000, newest_first: bool = True) -> List[Dict[str, Any]]:
    """
    Return events where status equals 'fail' (case-insensitive).
    """
    session = get_session()
    try:
        q = session.query(Event).filter(Event.status.ilike("fail"))
        q = q.order_by(Event.timestamp.desc() if newest_first else Event.timestamp.asc())
        rows = q.limit(limit).all()
        return [_row_to_dict(r) for r in rows]
    finally:
        session.close()

def print_valid_users(limit: int = 10000, newest_first: bool = True):
    """
    Affiche ligne par ligne tous les usernames valides.
    """
    session = get_session()
    try:
        q = session.query(Event.subject).filter(
            or_(
                Event.details.ilike("AADSTS50126"),
                Event.status.ilike("success")
            )
        )
        q = q.order_by(Event.timestamp.desc() if newest_first else Event.timestamp.asc())
        q = q.limit(limit)
        seen = set()
        for (subject,) in q.all():
            if subject and subject not in seen:
                print(subject)
                seen.add(subject)
    finally:
        session.close()

def query_events(status: Optional[str] = None,
                 subject: Optional[str] = None,
                 target: Optional[str] = None,
                 since: Optional[datetime.datetime] = None,
                 limit: int = 10000) -> List[Dict[str, Any]]:
    """
    Flexible query to fetch events by filters.
    """
    session = get_session()
    try:
        q = session.query(Event)
        if status:
            q = q.filter(Event.status == status)
        if subject:
            q = q.filter(Event.subject == subject)
        if target:
            q = q.filter(Event.target == target)
        if since:
            q = q.filter(Event.timestamp >= since)
        q = q.order_by(Event.timestamp.desc()).limit(limit)
        rows = q.all()
        return [_row_to_dict(r) for r in rows]
    finally:
        session.close()

def export_csv(path: str = "events_export.csv", rows: Optional[List[Dict[str, Any]]] = None,
               query_limit: int = 10000) -> str:
    """
    Export either provided rows or the most recent `query_limit` events to CSV.
    Returns the output path.
    """
    session = get_session()
    try:
        if rows is None:
            q = session.query(Event).order_by(Event.timestamp.desc()).limit(query_limit)
            rows = [_row_to_dict(r) for r in q.all()]
        fieldnames = ["id", "timestamp", "subject", "password", "target", "status", "ip", "details", "run_id"]
        with open(path, "w", newline='', encoding='utf-8') as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for r in rows:
                writer.writerow({k: r.get(k) for k in fieldnames})
        if LOGGER:
            LOGGER.info(f"[DB] Exported {len(rows)} rows to {path}")
        return path
    finally:
        session.close()

def purge_older_than(days: int = 90) -> int:
    """
    Delete events older than `days`. Returns number of deleted rows.
    """
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=days)
    session = get_session()
    try:
        q = session.query(Event).filter(Event.timestamp < cutoff)
        count = q.count()
        q.delete(synchronize_session=False)
        session.commit()
        if LOGGER:
            LOGGER.info(f"[DB] Purged {count} events older than {days} days")
        return count
    finally:
        session.close()

def _row_to_dict(row: Event) -> Dict[str, Any]:
    return {
        "id": row.id,
        "timestamp": row.timestamp.isoformat() if row.timestamp else None,
        "subject": row.subject,
        "password": row.password,
        "target": row.target,
        "status": row.status,
        "ip": row.ip,
        "details": row.details,
        "run_id": row.run_id,
    }

def has_user_password_been_tested(username: str, password: str) -> bool:
    """
    Retourne True si on trouve au moins une ligne où:
      - Event.subject == username
    ET
      - (Event.target == password)
    """
    if not username or not password:
        return False
    session = get_session()
    try:
        q = session.query(Event).filter(
            Event.subject == username, Event.password == password
        ).limit(1)
        return q.count() > 0
    finally:
        session.close()

def has_user_been_pwned(username: str) -> bool:
    """
    Retourne True si on trouve au moins une ligne où:
      - Event.subject == username
    ET
      - (Event.status == "success")
    """
    if not username:
        return False
    session = get_session()
    try:
        q = session.query(Event).filter(
            Event.subject == username, Event.status == "success"
        ).limit(1)
        return q.count() > 0
    finally:
        session.close()