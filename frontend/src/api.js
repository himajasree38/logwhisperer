// The one backend call lives here. Keys stay on the backend; the app never sees them.
// Local development talks to the backend on port 8000. A production build is
// served by the backend itself (see server.py), so it calls its own origin.
const API_BASE =
  import.meta.env.VITE_API_BASE ?? (import.meta.env.PROD ? "" : "http://localhost:8000");
// The three agents can take a while; give up before the audience does.
const ASK_TIMEOUT_MS = 120000;

import mockResponse from "../../prompts/mock_response.json";

/**
 * Ask the agents a question.
 * Returns { data, isMock, error }.
 * - Backend not there yet (unreachable, or no /ask route): the mock contract
 *   example, flagged with isMock so the UI can say so.
 * - Backend there but failing (5xx, bad JSON, timeout): error set, no mock — a
 *   canned answer must never stand in for a real one that went wrong.
 */
export async function ask(question) {
  let res;
  try {
    res = await fetch(`${API_BASE}/ask`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question }),
      signal: AbortSignal.timeout(ASK_TIMEOUT_MS),
    });
  } catch (err) {
    if (err.name === "TimeoutError") {
      return { error: "The agents took too long to answer. Try asking again." };
    }
    console.warn("[LogWhisperer] /ask unreachable, using mock:", err.message);
    return { data: normalize(mockResponse), isMock: true };
  }

  if (res.status === 404 || res.status === 405) {
    console.warn(`[LogWhisperer] no /ask route yet (${res.status}), using mock`);
    return { data: normalize(mockResponse), isMock: true };
  }

  try {
    if (!res.ok) throw new Error(`/ask returned ${res.status}`);
    return { data: normalize(await res.json()), isMock: false };
  } catch (err) {
    console.warn("[LogWhisperer] /ask failed:", err.message);
    return { error: "Something went wrong answering that. Try asking again, or rephrase the question." };
  }
}

/**
 * Run the one-click investigation. Returns { data } or { error }.
 * There is no mock for this: a canned attack report would be a fabricated finding.
 */
export async function investigate() {
  try {
    const res = await fetch(`${API_BASE}/investigate`, {
      method: "POST",
      signal: AbortSignal.timeout(ASK_TIMEOUT_MS),
    });
    if (!res.ok) throw new Error(`/investigate returned ${res.status}`);
    const data = await res.json();
    if (data.error || !Array.isArray(data.steps)) throw new Error(data.error || "unexpected reply");
    return { data };
  } catch (err) {
    console.warn("[LogWhisperer] /investigate failed:", err.message);
    return { error: "The investigation could not run. Check that the backend is up, then try again." };
  }
}

/** True when the backend answers its health check. */
export async function backendIsUp() {
  try {
    const res = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(4000) });
    return res.ok;
  } catch {
    return false;
  }
}

/** Guard every contract field so a missing key can never blank the screen. */
function normalize(raw) {
  const risk = ["low", "medium", "high"].includes(raw?.risk) ? raw.risk : "low";
  return {
    answer: raw?.answer || "No answer came back.",
    risk,
    next_steps: Array.isArray(raw?.next_steps) ? raw.next_steps : [],
    sql: raw?.sql || "",
    rows: Array.isArray(raw?.rows) ? raw.rows : [],
    timeline: Array.isArray(raw?.timeline) ? raw.timeline : [],
    stats: normalizeStats(raw?.stats),
    guild_session_url: safeUrl(raw?.guild_session_url),
  };
}

/** Only real numbers reach the stats line; anything else hides it. */
function normalizeStats(stats) {
  if (stats?.rows_scanned == null || stats?.query_ms == null) return null;
  const rows = Number(stats?.rows_scanned);
  const ms = Number(stats?.query_ms);
  if (!Number.isFinite(rows) || !Number.isFinite(ms)) return null;
  return { rows_scanned: rows, query_ms: ms };
}

/** The link is rendered as an href, so accept https only. */
function safeUrl(value) {
  return typeof value === "string" && value.startsWith("https://") ? value : null;
}
