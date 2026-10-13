import { useMask } from "../settings.js";

const dayLabel = (day) =>
  new Date(`${day}T00:00:00`).toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" });

const millions = (n) => (n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n.toLocaleString());

/** One row per day of data: did the outlier test find a suspect, and was the red team active? */
export default function Scan({ data, onInvestigate, busy }) {
  const mask = useMask();
  const flagged = data.days.filter((d) => d.suspects.length);
  const logins = data.days.reduce((sum, d) => sum + d.logins, 0);
  const labelled = data.days.some((d) => d.red_team);

  return (
    <div className="bubble bubble--agent">
      <div className="bubble__top">
        <span className="chip">Scan</span>
      </div>
      <p className="answer answer--headline">
        {flagged.length === 0
          ? `No day out of ${data.days.length} has a computer far outside normal.`
          : `${flagged.length} of ${data.days.length} days have a computer far outside normal.`}
      </p>
      <p className="stats">
        <strong>{data.days.length} days</strong> · <strong>{millions(logins)} logins</strong> ·{" "}
        <strong>{millions(data.stats.rows_scanned)} rows</strong> scanned in{" "}
        <strong>{(data.stats.query_ms / 1000).toFixed(1)} s</strong> · ClickHouse
      </p>

      <ol className="days">
        {data.days.map((d) => {
          const suspect = d.suspects[0];
          const active = d.red_team?.events > 0;
          return (
            <li key={d.day} className={`days__row ${suspect ? "is-flagged" : ""}`}>
              <span className="days__date">{dayLabel(d.day)}</span>
              <span className="days__finding">
                {suspect ? (
                  <>
                    <strong>{mask(suspect.computer)}</strong> reached {suspect.targets} machines with{" "}
                    {suspect.accounts} accounts
                    {suspect.times_normal ? ` (${suspect.times_normal}× normal)` : ""}
                  </>
                ) : (
                  <span className="days__quiet">Nothing far outside normal</span>
                )}
                {labelled && (
                  <span className="days__truth">
                    {active
                      ? `Red team: ${d.red_team.events} logins from ${mask(d.red_team.computers.join(", "))}`
                      : "Red team: not active"}
                    {" · "}
                    {verdict(suspect, d.red_team)}
                  </span>
                )}
              </span>
              <button className="btn btn--small" disabled={busy} onClick={() => onInvestigate(d.day)}>
                Investigate
              </button>
            </li>
          );
        })}
      </ol>

      {labelled && (
        <p className="score__note">
          The red-team lines come from the labels published with the LANL dataset and are added after
          the scan. The scan never reads them.
        </p>
      )}
    </div>
  );
}

/** Plain words for how the scan's call on a day compares with the labels. */
function verdict(suspect, redTeam) {
  const active = redTeam.events > 0;
  if (suspect && active) {
    return redTeam.computers.includes(suspect.computer) ? "caught" : "flagged a different computer";
  }
  if (suspect) return "flagged, no labelled activity";
  return active ? "missed" : "correctly quiet";
}
