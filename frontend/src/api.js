// The one backend call lives here. Keys stay on the backend; the app never sees them.
// Local development talks to the backend on port 8000. A production build is
// served by the backend itself (see server.py), so it calls its own origin.
const API_BASE =
  import.meta.env.VITE_API_BASE ?? (import.meta.env.PROD ? "" : "http://localhost:8000");
// The three agents can take a while; give up before the audience does.
const ASK_TIMEOUT_MS = 120000;

import mockResponse from "../../prompts/mock_response.json";

const PASSCODE_KEY = "logwhisperer.passcode";

/** A hosted demo can be locked with a passcode; it is kept for this tab only. */
export function setPasscode(code) {
  try {
    sessionStorage.setItem(PASSCODE_KEY, code);
  } catch {
    /* storage blocked: the code will have to be entered again */
  }
}

function post(path, body) {
  let passcode = "";
  try {
    passcode = sessionStorage.getItem(PASSCODE_KEY) || "";
  } catch {
    /* no stored code */
  }
  return fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(passcode && { "X-Passcode": passcode }) },
    body: JSON.stringify(body || {}),
    signal: AbortSignal.timeout(ASK_TIMEOUT_MS),
  });
}

/** Turn a locked or rate-limited reply into { needsPasscode } or { error }; otherwise null. */
async function refusal(res) {
  if (res.status === 401) return { needsPasscode: true };
  if (res.status === 429) {
    const body = await res.json().catch(() => ({}));
    return { error: body.error || "This demo is busy. Please try again later." };
  }
  return null;
}

/**
 * Ask the agents a question.
 * Returns { data, isMock, error, needsPasscode }.
 * - Backend not there yet (unreachable, or no /ask route): the mock contract
 *   example, flagged with isMock so the UI can say so.
 * - Backend there but failing (5xx, bad JSON, timeout): error set, no mock — a
 *   canned answer must never stand in for a real one that went wrong.
 * `day` scopes the question to one day; `history` carries earlier turns so
 * follow-ups like "what did that account do next?" can be resolved.
 */
export async function ask(question, { day, history } = {}) {
  let res;
  try {
    res = await post("/ask", { question, day, history });
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
  const refused = await refusal(res);
  if (refused) return refused;

  try {
    if (!res.ok) throw new Error(`/ask returned ${res.status}`);
    return { data: normalize(await res.json()), isMock: false };
  } catch (err) {
    console.warn("[LogWhisperer] /ask failed:", err.message);
    return { error: "Something went wrong answering that. Try asking again, or rephrase the question." };
  }
}

/** Shared by the investigation and the scan: POST, then check the reply has `field`. */
async function run(path, body, field, failure) {
  try {
    const res = await post(path, body);
    const refused = await refusal(res);
    if (refused) return refused;
    if (!res.ok) throw new Error(`${path} returned ${res.status}`);
    const data = await res.json();
    if (data.error || !Array.isArray(data[field])) throw new Error(data.error || "unexpected reply");
    return { data };
  } catch (err) {
    console.warn(`[LogWhisperer] ${path} failed:`, err.message);
    return { error: failure };
  }
}

/**
 * Run the one-click investigation, for one day or for all the data.
 * There is no mock for this: a canned attack report would be a fabricated finding.
 */
export const investigate = (day) =>
  run("/investigate", { day }, "steps",
    "The investigation could not run. Check that the backend is up, then try again.");

/** Run the outlier test across every day of data. */
export const scan = () =>
  run("/scan", {}, "days", "The scan could not run. Check that the backend is up, then try again.");

/** Days of data available, oldest first: [{ day, logins }]. Empty if the backend is down. */
export async function getDays() {
  try {
    const res = await fetch(`${API_BASE}/days`, { signal: AbortSignal.timeout(8000) });
    const body = await res.json();
    return Array.isArray(body.days) ? body.days : [];
  } catch {
    return [];
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
