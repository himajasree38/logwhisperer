import { useState, useSyncExternalStore } from "react";
import RiskBadge from "./RiskBadge.jsx";
import CopyButton from "./CopyButton.jsx";
import { canSpeak, getSpeakingId, speak, stopSpeaking, subscribeSpeech, briefingText } from "../speech.js";
import { useMask } from "../settings.js";

/** The report from a one-click investigation, with every step that led to it. */
export default function Investigation({ id, data }) {
  const mask = useMask();
  const [open, setOpen] = useState(false);
  const speaking = useSyncExternalStore(subscribeSpeech, getSpeakingId) === id;
  const briefing = briefingText({ answer: `${data.headline} ${data.summary}`, next_steps: data.actions });
  const { stats } = data;

  return (
    <div className="bubble bubble--agent">
      <div className="bubble__top">
        <RiskBadge risk={data.risk} />
        <span className="chip">Investigation</span>
      </div>

      <p className="answer answer--headline">{mask(data.headline)}</p>
      <p className="report">{mask(data.summary)}</p>

      {data.actions.length > 0 && (
        <div className="steps">
          <h3 className="steps__title">What to do</h3>
          <ol>
            {data.actions.map((action, i) => (
              <li key={i}>{mask(action)}</li>
            ))}
          </ol>
        </div>
      )}

      <p className="stats">
        <strong>{stats.queries} queries</strong> · <strong>{formatRows(stats.rows_scanned)} rows</strong> scanned
        in <strong>{(stats.query_ms / 1000).toFixed(1)} s</strong> · ClickHouse · no question asked
      </p>

      {data.scorecard && <Scorecard scorecard={data.scorecard} />}

      <div className="bubble__actions">
        {canSpeak && (
          <button className={`btn btn--ghost ${speaking ? "is-speaking" : ""}`}
                  onClick={speaking ? stopSpeaking : () => speak(briefing, id)}>
            {speaking && <span className="bars" aria-hidden="true"><i /><i /><i /><i /></span>}
            {speaking ? "Stop briefing" : "Play briefing"}
          </button>
        )}
        <CopyButton text={mask([data.headline, data.summary, ...data.actions].join("\n"))} label="Copy report" />
        <button className="link-btn" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
          {open ? "Hide the steps" : `How it was found (${data.steps.length} steps)`}
        </button>
      </div>

      {open && (
        <ol className="trail">
          {data.steps.map((step, i) => (
            <Step key={i} step={step} mask={mask} />
          ))}
        </ol>
      )}
    </div>
  );
}

const SCORE_ROWS = [
  { key: "computers", label: "Attack computers" },
  { key: "accounts", label: "Attacker accounts" },
  { key: "events", label: "Attack logins" },
];

/** How the findings compare with what LANL's red team recorded doing. */
function Scorecard({ scorecard }) {
  return (
    <div className="score">
      <h3 className="steps__title">Checked against the real attack</h3>
      <div className="score__grid">
        {SCORE_ROWS.map(({ key, label }) => {
          const s = scorecard[key];
          const extra = s.flagged - s.correct;
          return (
            <div key={key} className="score__tile">
              <span className="score__value">{s.correct.toLocaleString()} of {s.real.toLocaleString()}</span>
              <span className="score__label">{label} found</span>
              <span className="score__extra">
                {extra === 0 ? "nothing else flagged" : `${extra.toLocaleString()} more flagged, not in the labels`}
              </span>
            </div>
          );
        })}
      </div>
      <p className="score__note">
        Compared afterwards with the red-team labels published with the LANL dataset. The
        investigation never reads them.
      </p>
    </div>
  );
}

function Step({ step, mask }) {
  const [showSql, setShowSql] = useState(false);
  return (
    <li className="trail__step">
      <div className="trail__head">
        <strong>{step.title}</strong>
        <span className="trail__stats">
          {formatRows(step.stats.rows_scanned)} rows · {step.stats.query_ms} ms
        </span>
      </div>
      <p className="trail__finding">{mask(step.finding)}</p>
      <button className="link-btn" onClick={() => setShowSql((v) => !v)} aria-expanded={showSql}>
        {showSql ? "Hide SQL" : "Show SQL"}
      </button>
      {showSql && <pre className="sql__code">{mask(step.sql)}</pre>}
    </li>
  );
}

function formatRows(n) {
  if (n >= 1e9) return `${(n / 1e9).toFixed(1)}B`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)}K`;
  return String(n);
}
