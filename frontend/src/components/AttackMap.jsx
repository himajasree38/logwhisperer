import { useEffect, useMemo, useRef, useState } from "react";
import { useMask } from "../settings.js";

const SIZE = 520;
const CENTER = SIZE / 2;
const GOLDEN_ANGLE = Math.PI * (3 - Math.sqrt(5));
const PLAY_MS = 6000;

const clock = (iso) => String(iso).slice(11, 16);

/**
 * The suspect computer in the middle and every machine it logged into around it.
 * Machines are placed in the order they were first reached, spiralling outward,
 * so distance from the centre is time. The slider replays the spread.
 */
export default function AttackMap({ suspects, edges }) {
  const mask = useMask();
  const [shown, setShown] = useState(edges.length);
  const [playing, setPlaying] = useState(false);
  const [hover, setHover] = useState(null);
  const frame = useRef(0);

  const nodes = useMemo(() => {
    const maxRadius = CENTER - 22;
    return edges.map((edge, i) => {
      const radius = 46 + (maxRadius - 46) * Math.sqrt((i + 1) / edges.length);
      const angle = i * GOLDEN_ANGLE;
      return {
        ...edge,
        x: CENTER + radius * Math.cos(angle),
        y: CENTER + radius * Math.sin(angle),
        r: Math.min(8, 3 + edge.accounts),
      };
    });
  }, [edges]);

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

  return (
    <figure className="viz">
      <figcaption className="viz__title">
        Machines {mask(name)} logged into, in the order it reached them
      </figcaption>

      <div className="viz__legend">
        <span><i className="key key--suspect" /> Suspect computer</span>
        <span><i className="key key--target" /> Machine it logged into</span>
        <span className="viz__note">Larger dot = more accounts used. Further out = later.</span>
      </div>

      <div className="map">
        <svg viewBox={`0 0 ${SIZE} ${SIZE}`} role="img"
             aria-label={`${edges.length} machines reached from ${name}`}>
          {nodes.slice(0, shown).map((n) => (
            <line key={`l-${n.target}`} className="map__edge" x1={CENTER} y1={CENTER} x2={n.x} y2={n.y} />
          ))}
          {nodes.slice(0, shown).map((n) => (
            <g key={n.target}
               onPointerEnter={() => setHover(n)}
               onPointerLeave={() => setHover((h) => (h === n ? null : h))}>
              <circle className="map__hit" cx={n.x} cy={n.y} r={12} />
              <circle className={`map__node ${hover === n ? "is-hover" : ""}`} cx={n.x} cy={n.y} r={n.r} />
            </g>
          ))}
          <circle className="map__suspect-ring" cx={CENTER} cy={CENTER} r={22} />
          <circle className="map__suspect" cx={CENTER} cy={CENTER} r={13} />
          <text className="map__label" x={CENTER} y={CENTER + 38} textAnchor="middle">{mask(name)}</text>
        </svg>

        {hover && (
          <div className="tooltip" style={{ left: `${(hover.x / SIZE) * 100}%`, top: `${(hover.y / SIZE) * 100}%` }}>
            <strong>{mask(hover.target)}</strong>
            <span>First reached {clock(hover.first_seen)}</span>
            <span>{hover.accounts} {hover.accounts === 1 ? "account" : "accounts"} · {hover.logins} {hover.logins === 1 ? "login" : "logins"}</span>
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
