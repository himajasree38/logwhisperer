import { useEffect, useMemo, useRef, useState } from "react";
import { useMask } from "../settings.js";

const W = 640;
const H = 520;
const SUSPECT = { x: 400, y: H / 2 };
// Fraction of a turn between successive machines. The golden ratio spreads points
// evenly whether it is applied to a full circle or, as here, to a wedge.
const GOLDEN_FRACTION = 0.381966;
// Machines fan out to the right of the suspect; the wedge on its left is kept
// clear for the lines coming in from the accounts' usual computers.
const FAN_DEGREES = 280;
const PLAY_MS = 6000;

const clock = (iso) => String(iso).slice(11, 16);
const radians = (degrees) => (degrees * Math.PI) / 180;

/**
 * Three layers, read left to right:
 *   the computers the stolen accounts normally work from,
 *   the suspect computer that used those accounts,
 *   and every machine it logged into.
 * Machines are placed in the order they were first reached, spiralling outward,
 * so distance from the suspect is time. The slider replays the spread.
 */
export default function AttackMap({ suspects, edges, accounts = [], homes = [] }) {
  const mask = useMask();
  const [shown, setShown] = useState(edges.length);
  const [playing, setPlaying] = useState(false);
  const [hover, setHover] = useState(null);
  const frame = useRef(0);

  const nodes = useMemo(
    () =>
      edges.map((edge, i) => {
        const radius = 46 + (225 - 46) * Math.sqrt((i + 1) / edges.length);
        const angle = radians(-FAN_DEGREES / 2 + ((i * GOLDEN_FRACTION) % 1) * FAN_DEGREES);
        return {
          ...edge,
          kind: "target",
          x: SUSPECT.x + radius * Math.cos(angle),
          y: SUSPECT.y + radius * Math.sin(angle),
          r: Math.min(8, 3 + edge.accounts),
        };
      }),
    [edges]
  );

  // One square per usual computer, on two staggered arcs to the left of the suspect.
  const homeNodes = useMemo(() => {
    const used = new Map(accounts.map((a) => [a.account, a]));
    const span = Math.min(56, Math.max(12, homes.length * 1.3));
    return homes.map((home, i) => {
      const t = homes.length > 1 ? i / (homes.length - 1) : 0.5;
      const angle = radians(180 - span / 2 + t * span);
      const radius = i % 2 ? 330 : 300;
      const account = used.get(home.account);
      return {
        ...home,
        kind: "home",
        firstUsed: account?.first_seen,
        targets: account?.targets,
        x: SUSPECT.x + radius * Math.cos(angle),
        y: SUSPECT.y + radius * Math.sin(angle),
      };
    });
  }, [homes, accounts]);

  useEffect(() => {
    if (!playing) return;
    const started = performance.now();
    const tick = (now) => {
      const progress = Math.min(1, (now - started) / PLAY_MS);
      setShown(Math.round(progress * edges.length));
      if (progress < 1) frame.current = requestAnimationFrame(tick);
      else setPlaying(false);
    };
    frame.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame.current);
  }, [playing, edges.length]);

  if (!edges.length) return null;
  const name = suspects.map((s) => s.computer).join(", ");
  const last = shown > 0 ? nodes[shown - 1] : null;
  // During a replay, an account's line appears once the suspect has started using it.
  const now = shown >= edges.length ? "9999" : last ? String(last.first_seen) : "";
  const inUse = (home) => !home.firstUsed || String(home.firstUsed) <= now;

  return (
    <figure className="viz">
      <figcaption className="viz__title">
        {homeNodes.length > 0
          ? `Stolen accounts' usual computers, ${mask(name)}, and the machines it logged into`
          : `Machines ${mask(name)} logged into, in the order it reached them`}
      </figcaption>

      <div className="viz__legend">
        {homeNodes.length > 0 && (
          <span><i className="key key--home" /> Usual computer of an account it used</span>
        )}
        <span><i className="key key--suspect" /> Suspect computer</span>
        <span><i className="key key--target" /> Machine it logged into</span>
        <span className="viz__note">
          Read left to right. Larger dot = more accounts used. Further from the suspect = later.
        </span>
      </div>

      <div className="map">
        <svg viewBox={`0 0 ${W} ${H}`} role="img"
             aria-label={`${homeNodes.length} usual computers, the suspect ${name}, and ${edges.length} machines it reached`}>
          {homeNodes.filter(inUse).map((n) => (
            <line key={`h-${n.account}`} className="map__theft" x1={n.x} y1={n.y} x2={SUSPECT.x} y2={SUSPECT.y} />
          ))}
          {nodes.slice(0, shown).map((n) => (
            <line key={`l-${n.target}`} className="map__edge" x1={SUSPECT.x} y1={SUSPECT.y} x2={n.x} y2={n.y} />
          ))}
          {homeNodes.map((n) => (
            <g key={n.account}
               onPointerEnter={() => setHover(n)}
               onPointerLeave={() => setHover((h) => (h === n ? null : h))}>
              <circle className="map__hit" cx={n.x} cy={n.y} r={11} />
              <rect className={`map__home ${inUse(n) ? "" : "is-waiting"} ${hover === n ? "is-hover" : ""}`}
                    x={n.x - 4} y={n.y - 4} width={8} height={8} rx={1.5} />
            </g>
          ))}
          {nodes.slice(0, shown).map((n) => (
            <g key={n.target}
               onPointerEnter={() => setHover(n)}
               onPointerLeave={() => setHover((h) => (h === n ? null : h))}>
              <circle className="map__hit" cx={n.x} cy={n.y} r={12} />
              <circle className={`map__node ${hover === n ? "is-hover" : ""}`} cx={n.x} cy={n.y} r={n.r} />
            </g>
          ))}
          <circle className="map__suspect-ring" cx={SUSPECT.x} cy={SUSPECT.y} r={22} />
          <circle className="map__suspect" cx={SUSPECT.x} cy={SUSPECT.y} r={13} />
          <text className="map__label" x={SUSPECT.x} y={SUSPECT.y + 38} textAnchor="middle">{mask(name)}</text>
          {homeNodes.length > 0 && (
            <>
              <text className="map__caption" x={62} y={22}>Accounts normally work here</text>
              <text className="map__caption" x={SUSPECT.x} y={22} textAnchor="middle">It logged into these</text>
            </>
          )}
        </svg>

        {hover && (
          <div className="tooltip" style={{ left: `${(hover.x / W) * 100}%`, top: `${(hover.y / H) * 100}%` }}>
            {hover.kind === "home" ? (
              <>
                <strong>{mask(hover.home)}</strong>
                <span>Usual computer of {mask(hover.account)}</span>
                {hover.firstUsed && <span>Suspect first used that account at {clock(hover.firstUsed)}</span>}
                {hover.targets != null && (
                  <span>and reached {hover.targets} {hover.targets === 1 ? "machine" : "machines"} with it</span>
                )}
              </>
            ) : (
              <>
                <strong>{mask(hover.target)}</strong>
                <span>First reached {clock(hover.first_seen)}</span>
                <span>
                  {hover.accounts} {hover.accounts === 1 ? "account" : "accounts"} · {hover.logins}{" "}
                  {hover.logins === 1 ? "login" : "logins"}
                </span>
              </>
            )}
          </div>
        )}
      </div>

      <div className="scrub">
        <button className="btn btn--small" onClick={() => setPlaying((p) => !p)}>
          {playing ? "Pause" : "Replay"}
        </button>
        <input type="range" min="0" max={edges.length} value={shown} aria-label="Replay the spread over time"
               onChange={(e) => { setPlaying(false); setShown(Number(e.target.value)); }} />
        <span className="scrub__label">
          <strong>{shown}</strong> of {edges.length} machines{last ? ` by ${clock(last.first_seen)}` : ""}
        </span>
      </div>
    </figure>
  );
}
