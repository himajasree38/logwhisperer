"""Load the first N days of LANL authentication logs into ClickHouse, with red-team labels.

ClickHouse pulls the files from LANL itself, so nothing is downloaded to this machine.

    python scripts/load_days.py --token <token> --days 16

Get the token by submitting the form at https://csr.lanl.gov/data/cyber1/ : the
download links it reveals look like /data-fence/<token>/cyber1/auth.txt.gz.

Creates two tables next to any existing ones:
  redteam        the 749 labelled red-team events
  auth_logs_v2   one row per login, partitioned by day, is_attack set from redteam

Then set AUTH_TABLE=auth_logs_v2 in .env.
"""
from pathlib import Path
import argparse, os, time

import clickhouse_connect
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

BASE = "https://csr.lanl.gov/data-fence/{token}/cyber1/{name}"
EPOCH = "2026-09-30 00:00:00"   # dataset second 0, the same mapping as the original one-day load
ROWS_PER_DAY_CEILING = 25_000_000   # generous: the busiest days hold about 20 million logins
AUTH_COLUMNS = ("time UInt32, src_user String, dst_user String, src_comp String, dst_comp String, "
                "auth_type String, logon_type String, auth_orientation String, result String")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--token", required=True, help="token from the LANL download form")
    parser.add_argument("--days", type=int, default=16, help="load days 1..N of the dataset")
    args = parser.parse_args()

    client = clickhouse_connect.get_client(
        host=os.getenv("CLICKHOUSE_HOST"), username=os.getenv("CLICKHOUSE_USER"),
        password=os.getenv("CLICKHOUSE_PASSWORD"), secure=True, send_receive_timeout=4 * 3600)
    redteam_url = BASE.format(token=args.token, name="redteam.txt.gz")
    auth_url = BASE.format(token=args.token, name="auth.txt.gz")

    client.command("CREATE TABLE IF NOT EXISTS redteam (time UInt32, src_user String, src_comp String, "
                   "dst_comp String) ENGINE = MergeTree ORDER BY time")
    client.command("TRUNCATE TABLE redteam")
    client.command(f"INSERT INTO redteam SELECT time, user, src, dst FROM url('{redteam_url}', 'CSV', "
                   "'time UInt32, user String, src String, dst String')")
    print("red-team events:", client.command("SELECT count() FROM redteam"))

    client.command(
        "CREATE TABLE IF NOT EXISTS auth_logs_v2 (time UInt32, src_user String, dst_user String, "
        "src_comp LowCardinality(String), dst_comp LowCardinality(String), auth_type LowCardinality(String), "
        "logon_type LowCardinality(String), auth_orientation LowCardinality(String), "
        "result LowCardinality(String), is_attack UInt8, timestamp DateTime) "
        "ENGINE = MergeTree PARTITION BY toDate(timestamp) ORDER BY (timestamp, src_user)")
    if client.command("SELECT count() FROM auth_logs_v2"):
        raise SystemExit("auth_logs_v2 already has rows. Truncate it first if you mean to reload.")

    # The file is sorted by time, so a row limit lets ClickHouse stop reading early
    # instead of pulling all 58 days. The time filter then trims to whole days.
    start = time.time()
    print(f"loading days 1 to {args.days} (this takes several minutes)...")
    client.command(
        f"INSERT INTO auth_logs_v2 SELECT time, src_user, dst_user, src_comp, dst_comp, auth_type, logon_type, "
        f"auth_orientation, result, (time, src_user, src_comp, dst_comp) IN "
        f"(SELECT time, src_user, src_comp, dst_comp FROM redteam) AS is_attack, "
        f"toDateTime('{EPOCH}') + time AS timestamp "
        f"FROM (SELECT * FROM url('{auth_url}', 'CSV', '{AUTH_COLUMNS}') "
        f"LIMIT {args.days * ROWS_PER_DAY_CEILING}) WHERE time < {args.days * 86400}",
        settings={"max_execution_time": 3 * 3600})

    rows, attacks, days, last = client.query(
        "SELECT count(), sum(is_attack), uniqExact(toDate(timestamp)), max(time) FROM auth_logs_v2").result_rows[0]
    print(f"{rows:,} logins over {days} days, {attacks} labelled attack logins, {time.time() - start:.0f}s")
    if last < args.days * 86400 - 3600:
        print("WARNING: the last day looks incomplete; raise ROWS_PER_DAY_CEILING and reload.")
    read_only = os.getenv("CLICKHOUSE_RO_USER")
    if read_only:
        client.command(f"GRANT SELECT ON auth_logs_v2 TO {read_only}")
        print(f"granted SELECT on auth_logs_v2 to {read_only}")


if __name__ == "__main__":
    main()
