import argparse
import datetime
import sys
from typing import Optional

from utils import (
    configure_logger,
    init_db,
    get_successful_events,
    get_failed_events,
    print_valid_users,
    query_events,
    export_csv,
    purge_older_than,
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Admin local DB viewer/exporter"
    )

    # db path
    parser.add_argument(
        "--db",
        default="events.db",
        help="Chemin vers la base SQLite (défaut: events.db)",
    )

    # init DB
    parser.add_argument(
        "--init",
        action="store_true",
        help="Initialiser/créer la base si besoin, puis quitter",
    )

    # lister les success
    parser.add_argument(
        "--list-success",
        action="store_true",
        help="Afficher les derniers événements avec status='success'",
    )

    # lister les fail
    parser.add_argument(
        "--list-fail",
        action="store_true",
        help="Afficher les derniers événements avec status='fail'",
    )

    # lister les users valides
    parser.add_argument(
        "--print-valid-users",
        action="store_true",
        help="Afficher les derniers événements avec status='success' ou details='AADSTS50126'",
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Limite de résultats à retourner (défaut: 50)",
    )
    parser.add_argument(
        "--oldest-first",
        action="store_true",
        help="Pour --list-success : trier du plus ancien au plus récent au lieu du plus récent d'abord",
    )

    # requête générique
    parser.add_argument(
        "--query",
        action="store_true",
        help="Faire une requête filtrée personnalisée",
    )
    parser.add_argument(
        "--status",
        help="Filtre statut exact (ex: success, invalid, timeout...)",
    )
    parser.add_argument(
        "--subject",
        help="Filtre sur subject (ex: un identifiant utilisateur)",
    )
    parser.add_argument(
        "--target",
        help="Filtre sur target (ex: URL / host / service)",
    )
    parser.add_argument(
        "--since",
        help="Filtre date minimale (format ISO 8601 ou YYYY-MM-DD). Ex: 2025-10-24 ou 2025-10-24T10:30:00",
    )

    # export CSV
    parser.add_argument(
        "--export",
        metavar="CSV_PATH",
        help="Exporter les derniers événements vers un CSV",
    )

    # purge
    parser.add_argument(
        "--purge",
        type=int,
        metavar="DAYS",
        help="Supprimer les événements plus vieux que DAYS jours. Ex: --purge 90",
    )

    # verbose logger
    parser.add_argument(
        "-V",
        "--verbose",
        action="store_true",
        default=False,
        help="Logger en DEBUG",
    )

    return parser.parse_args()


def parse_since(since_str: Optional[str]) -> Optional[datetime.datetime]:
    """
    Transforme une string en datetime UTC naive.
    Accepte:
      - "2025-10-24"
      - "2025-10-24T10:30:00"
    Retourne None si since_str est None.
    """
    if not since_str:
        return None

    # Essai format complet ISO-like
    try:
        return datetime.datetime.fromisoformat(since_str)
    except ValueError:
        pass

    # Essai date seule YYYY-MM-DD
    try:
        return datetime.datetime.strptime(since_str, "%Y-%m-%d")
    except ValueError:
        raise ValueError(
            f"Format invalide pour --since : {since_str}. "
            f"Utilise YYYY-MM-DD ou YYYY-MM-DDTHH:MM:SS"
        )


def print_rows(rows):
    """
    Affichage console propre des résultats.
    rows = liste de dicts {id, timestamp, subject, target, status, details, run_id}
    """
    if not rows:
        print("(aucun résultat)")
        return

    # petit rendu style tableau texte
    for r in rows:
        print("=" * 60)
        print(f"id        : {r.get('id')}")
        print(f"timestamp : {r.get('timestamp')}")
        print(f"subject   : {r.get('subject')}")
        print(f"password   : {r.get('password')}")
        print(f"target    : {r.get('target')}")
        print(f"status    : {r.get('status')}")
        print(f"run_id    : {r.get('run_id')}")
        print(f"details   : {r.get('details')}")
    print("=" * 60)


def main():
    args = parse_args()
    print(args)

    LOGGER = configure_logger(verbose=args.verbose, logfile_prefix="DBADMIN")

    # Init DB (toujours) pour avoir une session, puis on agira selon les flags
    init_db(args.db, echo=False)

    # 1. --init seul => on sort après init
    if args.init and not (args.list_success or args.list_fail or args.print_valid_users or args.query or args.export or args.purge):
        LOGGER.info(f"DB initialisée à {args.db}")
        return

    # 2. purge si demandé
    if args.purge is not None:
        deleted = purge_older_than(days=args.purge)
        LOGGER.info(f"Purge: {deleted} lignes supprimées (> {args.purge} jours).")

    # 3. list-success
    if args.list_success:
        rows = get_successful_events(
            limit=args.limit,
            newest_first=not args.oldest_first
        )
        print_rows(rows)

    # 3bis. list-fail
    if args.list_fail:
        rows = get_failed_events(
            limit=args.limit,
            newest_first=not args.oldest_first
        )
        print_rows(rows)

    # 3ter. print_valid_users
    if args.print_valid_users:
        rows = print_valid_users(
            limit=args.limit,
            newest_first=not args.oldest_first
        )
        print_rows(rows)

    # 4. requête custom
    if args.query:
        try:
            since_dt = parse_since(args.since)
        except ValueError as e:
            LOGGER.error(str(e))
            sys.exit(1)

        rows = query_events(
            status=args.status,
            subject=args.subject,
            target=args.target,
            since=since_dt,
            limit=args.limit,
        )
        print_rows(rows)

    # 5. export CSV
    if args.export:
        # si l'utilisateur a fait --query, on peut réutiliser ces résultats.
        # Pour garder ça simple, on refait une requête.
        try:
            since_dt = parse_since(args.since)
        except ValueError as e:
            LOGGER.error(str(e))
            sys.exit(1)

        # Si l'utilisateur a passé --query, on respecte les mêmes filtres dans l'export.
        # Sinon, on exporte les derniers "query_limit" (limit ~ args.limit).
        if args.query:
            rows = query_events(
                status=args.status,
                subject=args.subject,
                target=args.target,
                since=since_dt,
                limit=args.limit,
            )
            out_path = export_csv(path=args.export, rows=rows)
        else:
            # export_csv sait interroger tout seul si rows=None
            out_path = export_csv(path=args.export, rows=None, query_limit=args.limit)

        LOGGER.info(f"Export CSV terminé -> {out_path}")


if __name__ == "__main__":
    main()
