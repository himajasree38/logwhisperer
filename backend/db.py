import os, re, time, datetime, threading
import clickhouse_connect
from dotenv import load_dotenv

load_dotenv()

MAX_QUERY_SECONDS = 30
_local = threading.local()

def _client():
    """One read-only client per thread: a ClickHouse session cannot run two queries at once,
    and the web server answers each request on its own thread."""
    if not hasattr(_local, "client"):
        _local.client = clickhouse_connect.get_client(
            host=os.getenv("CLICKHOUSE_HOST"),
            username=os.getenv("CLICKHOUSE_RO_USER"),
            password=os.getenv("CLICKHOUSE_RO_PASSWORD"),
            secure=True,
        )
    return _local.client

def clean_sql(text: str) -> str:
    """Remove ```sql fences, extra spaces, and a trailing semicolon."""
    text = re.sub(r"```(?:sql)?", "", text, flags=re.IGNORECASE).strip()
    return text.rstrip(";").strip()

def run_sql(query: str, max_rows: int = 100) -> dict:
    sql = clean_sql(query)

    # Safety: only one read-only statement allowed
    if not re.match(r"^(SELECT|WITH)\b", sql, flags=re.IGNORECASE):
        raise ValueError("Only SELECT queries are allowed.")
    if ";" in sql:
        raise ValueError("Only one query at a time is allowed.")
    if not re.search(r"\bLIMIT\s+\d+", sql, flags=re.IGNORECASE):
        sql = f"{sql}\nLIMIT {max_rows}"

    start = time.time()
    result = _client().query(sql, settings={"max_execution_time": MAX_QUERY_SECONDS})
    ms = round((time.time() - start) * 1000)

    rows = []
    for r in result.result_rows:
        row = {}
        for col, val in zip(result.column_names, r):
            if isinstance(val, (datetime.datetime, datetime.date)):
                val = val.isoformat()
            row[col] = val
        rows.append(row)

    summary = result.summary or {}
    rows_scanned = int(summary.get("read_rows", 0) or 0)

    return {
        "sql": sql,
        "columns": list(result.column_names),
        "rows": rows,
        "stats": {"rows_scanned": rows_scanned, "query_ms": ms},
    }

if __name__ == "__main__":
    out = run_sql("""
        SELECT src_user, uniqExact(dst_comp) AS computers, sum(is_attack) AS attacks
        FROM auth_logs
        GROUP BY src_user
        ORDER BY attacks DESC, computers DESC
        LIMIT 5
    """)
    print(out["stats"])
    for row in out["rows"]:
        print(row)
    try:
        run_sql("DROP TABLE auth_logs")
    except ValueError as e:
        print("Blocked as expected:", e)
