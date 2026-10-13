import { useState } from "react";

const W = 520, H = 190;
const PAD = { top: 10, right: 8, bottom: 24, left: 30 };
const GAP = 2; // surface gap between stacked segments

const clock = (iso) => String(iso).slice(11, 16);

/** Round a maximum up to a tidy axis ceiling. */
function niceMax(value) {
  const step = value <= 20 ? 5 : value <= 50 ? 10 : value <= 100 ? 20 : 50;
  return Math.max(step, Math.ceil(value / step) * step);
}

/** Logins from the suspect in each half hour: succeeded stacked under failed. */
export default function ActivityChart({ activity, name }) {
  const [hover, setHover] = useState(null);
  if (!activity.length) return null;

  const top = niceMax(Math.max(...activity.map((a) => a.succeeded + a.failed)));
  const plotW = W - PAD.left - PAD.right;
  const plotH = H - PAD.top - PAD.bottom;
  const band = plotW / activity.length;
  const bar = Math.min(24, band - 4);
  const y = (v) => PAD.top + plotH - (v / top) * plotH;
  const ticks = [0, top / 2, top];

  return (
    <figure className="viz">
      <figcaption className="viz__title">Logins from {name} every 30 minutes</figcaption>
      <div className="viz__legend">
        <span><i className="key key--s1" /> Succeeded</span>
        <span><i className="key key--s2" /> Failed</span>
      </div>

      <div className="chart">
        <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Logins from ${name} through the day`}>
          {ticks.map((t) => (
            <g key={t}>
              <line className="chart__grid" x1={PAD.left} x2={W - PAD.right} y1={y(t)} y2={y(t)} />
              <text className="chart__tick" x={PAD.left - 6} y={y(t) + 4} textAnchor="end">{t}</text>
            </g>
          ))}
          {activity.map((a, i) => {
            const x = PAD.left + i * band + (band - bar) / 2;
            const okH = (a.succeeded / top) * plotH;
            const failH = (a.failed / top) * plotH;
            const failY = y(a.succeeded + a.failed);
            const lift = a.succeeded && a.failed ? GAP : 0;
            return (
              <g key={a.slot} onPointerEnter={() => setHover(i)} onPointerLeave={() => setHover(null)}>
                <rect className="chart__hit" x={PAD.left + i * band} y={PAD.top} width={band} height={plotH} />
                {a.succeeded > 0 && (
                  <path className="chart__s1" d={barPath(x, y(a.succeeded), bar, okH, a.failed ? 0 : 4)} />
                )}
                {a.failed > 0 && (
                  <path className="chart__s2" d={barPath(x, failY, bar, Math.max(1, failH - lift), 4)} />
                )}
                {i % 4 === 0 && (
                  <text className="chart__tick" x={x + bar / 2} y={H - 6} textAnchor="middle">{clock(a.slot)}</text>
                )}
              </g>
            );
          })}
          <line className="chart__axis" x1={PAD.left} x2={W - PAD.right} y1={y(0)} y2={y(0)} />
        </svg>

        {hover !== null && (
          <div className="tooltip" style={{
            left: `${((PAD.left + hover * band + band / 2) / W) * 100}%`,
            top: `${(y(activity[hover].succeeded + activity[hover].failed) / H) * 100}%`,
          }}>
            <strong>{clock(activity[hover].slot)}</strong>
            <span><i className="key key--s1" /> {activity[hover].succeeded} succeeded</span>
            <span><i className="key key--s2" /> {activity[hover].failed} failed</span>
          </div>
        )}
      </div>
    </figure>
  );
}

/** A bar with its top corners rounded by `r` and a square base. */
function barPath(x, top, width, height, r) {
  const radius = Math.min(r, width / 2, height);
  return `M${x},${top + height} V${top + radius} Q${x},${top} ${x + radius},${top} `
    + `H${x + width - radius} Q${x + width},${top} ${x + width},${top + radius} V${top + height} Z`;
}
