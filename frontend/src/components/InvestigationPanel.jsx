import { useState } from "react";
import AttackMap from "./AttackMap.jsx";
import ActivityChart from "./ActivityChart.jsx";
import ResultsTable from "./ResultsTable.jsx";
import { useMask } from "../settings.js";

const VIEWS = [
  { id: "map", label: "Map" },
  { id: "accounts", label: "Accounts" },
  { id: "machines", label: "Machines" },
];

/** Right-hand panel for an investigation: the map and chart, or the same data as tables. */
export default function InvestigationPanel({ data }) {
  const mask = useMask();
  const [view, setView] = useState("map");

  if (!data.suspects.length) {
    return (
      <div className="panel__body">
        <p className="hint">No computer stood out, so there is nothing to map.</p>
      </div>
    );
  }
  const name = mask(data.suspects.map((s) => s.computer).join(", "));

  return (
    <div className="panel__body">
      <div className="tabs" role="tablist">
        {VIEWS.map((v) => (
          <button key={v.id} role="tab" aria-selected={view === v.id}
                  className={`tabs__item ${view === v.id ? "is-on" : ""}`} onClick={() => setView(v.id)}>
            {v.label}
            {v.id === "accounts" && ` (${data.accounts.length})`}
            {v.id === "machines" && ` (${data.edges.length})`}
          </button>
        ))}
      </div>

      {view === "map" && (
        <>
          <AttackMap suspects={data.suspects} edges={data.edges} />
          <ActivityChart activity={data.activity} name={name} />
        </>
      )}
      {view === "accounts" && (
        <>
          <p className="hint">Accounts that logged in successfully from {name}. Treat their passwords as stolen.</p>
          <ResultsTable rows={data.accounts} />
        </>
      )}
      {view === "machines" && (
        <>
          <p className="hint">Machines {name} logged into, in the order it first reached them.</p>
          <ResultsTable rows={data.edges} />
        </>
      )}
    </div>
  );
}
