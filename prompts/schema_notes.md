Table: auth_logs (ClickHouse, read-only). One row = one Windows authentication event in a company network, from the LANL dataset. The table holds one or more full days. If you are not told which day the analyst is looking at, "yesterday" means the most recent day in the table.

In any text column, "?" means unknown.

Columns:
- timestamp (DateTime): when the event happened, e.g. 2026-10-08 14:32:05. Use this for all time questions. For one day, filter with toDate(timestamp) = '2026-10-08'.
- time (UInt32): seconds since the dataset started, e.g. 742325. Ignore; use timestamp.
- src_user (String): account that started the login, e.g. U66@DOM1.
- dst_user (String): account used on the destination computer, e.g. U66@DOM1 or SYSTEM@C1234.
- src_comp (String): computer the login came from, e.g. C17693.
- dst_comp (String): computer being logged into, e.g. C1234. Can equal src_comp for local logins.
- auth_type (String): authentication package, e.g. NTLM, Kerberos, Negotiate, or ?.
- logon_type (String): how the login happened, e.g. Network, Interactive, Batch, Service, RemoteInteractive, or ?.
- auth_orientation (String): kind of event, e.g. LogOn, LogOff, TGT, TGS, AuthMap.
- result (String): Success or Fail.
- is_attack (UInt8): e.g. 0. NEVER use this column in any query. It is hidden ground truth.

Tips:
- Accounts ending in $ (e.g. C586$@DOM1) are computer accounts, not people.
- People accounts start with U (src_user LIKE 'U%').
- When counting the accounts a computer used, count people's accounts only (src_user LIKE 'U%'). Servers pass thousands of computer accounts through every day, and that is routine.
- Moving between computers = src_comp != dst_comp.
- Number of different computers an account reached = uniqExact(dst_comp).
- Hour of day = toHour(timestamp).
