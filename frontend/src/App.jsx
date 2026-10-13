import { useCallback, useEffect, useRef, useState } from "react";
import { ask, backendIsUp, getDays, investigate, scan, setPasscode } from "./api.js";
import { useVoice } from "./useVoice.js";
import { HISTORY_KEY, MaskProvider, maskFor, useSettings } from "./settings.js";
import { briefingText, setPreferredVoice, speak, stopSpeaking } from "./speech.js";
import Answer from "./components/Answer.jsx";
import Timeline from "./components/Timeline.jsx";
import PushToTalk from "./components/PushToTalk.jsx";
import Settings from "./components/Settings.jsx";
import Investigation from "./components/Investigation.jsx";
import InvestigationPanel from "./components/InvestigationPanel.jsx";
import Scan from "./components/Scan.jsx";
import "./App.css";

const DEMO_QUESTIONS = [
  "Which accounts logged into the most different computers that day?",
  "Which accounts had the most failed logins that day?",
  "Were there any logins at unusual hours, between midnight and 5 AM?",
];

const dayLabel = (day) =>
  new Date(`${day}T00:00:00`).toLocaleDateString(undefined, { month: "short", day: "numeric" });

/** Earlier answered questions, oldest first, so the backend can resolve follow-ups. */
function conversation(messages) {
  const turns = [];
  messages.forEach((msg, i) => {
    if (msg.role === "agent" && msg.data.sql && messages[i - 1]?.role === "user") {
      turns.push({ question: messages[i - 1].text, sql: msg.data.sql, answer: msg.data.answer });
    }
    // An investigation counts as a turn too, so "that computer" can mean its suspect.
    if (msg.role === "investigation" && msg.data.suspects.length) {
      turns.push({
        question: "Investigate this day: is there a compromised computer?",
        sql: msg.data.steps[1]?.sql || "",
        answer: `${msg.data.headline} ${msg.data.summary}`,
      });
    }
  });
  return turns.slice(-3);
}

function loadHistory(enabled) {
  if (!enabled) return [];
  try {
    return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
  } catch {
    return [];
  }
}

export default function App() {
  const [settings, updateSettings] = useSettings();
  const [messages, setMessages] = useState(() => loadHistory(settings.saveHistory));
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [busyText, setBusyText] = useState("");
  const [elapsed, setElapsed] = useState(0);
  const [online, setOnline] = useState(null); // null until the first check
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [days, setDays] = useState([]);
  const [day, setDay] = useState("");
  const [locked, setLocked] = useState(false); // the hosted demo asked for a passcode
  const messagesRef = useRef(messages);
  const dayRef = useRef(day);
  const scrollRef = useRef(null);
  const inputRef = useRef(null);
  const countRef = useRef(messages.length);
  const autoSpeakRef = useRef(settings.autoSpeak);

  useEffect(() => {
    countRef.current = messages.length;
    autoSpeakRef.current = settings.autoSpeak;
    messagesRef.current = messages;
    dayRef.current = day;
  }, [messages, settings.autoSpeak, day]);

  // Finish any request the same way: show the result, or the reason there is none.
  const finish = useCallback((result, toMessage) => {
    if (result.needsPasscode) setLocked(true);
    setMessages((prev) => [
      ...prev,
      result.needsPasscode
        ? { role: "error", text: "This demo is locked. Enter the passcode, then try again." }
        : result.error
          ? { role: "error", text: result.error }
          : toMessage(result),
    ]);
    setBusy(false);
    return !result.needsPasscode && !result.error;
  }, []);

  useEffect(() => setPreferredVoice(settings.voice), [settings.voice]);

  // The newest answer drives the right-hand panel.
  // The side panel can show the latest investigation's map or the latest answer's
  // results. It follows whichever is newer, and the reader can switch back.
  const lastOf = (role) => messages.findLastIndex((m) => m.role === role);
  const mapAt = lastOf("investigation");
  const resultsAt = lastOf("agent");
  const scanAt = lastOf("scan");
  // A pick only lasts until the next message, which hands the panel back to the newest.
  const [sidePick, setSidePick] = useState(null); // { view: "map" | "results", at: message count }
  const side =
    sidePick?.at === messages.length ? sidePick.view : mapAt > resultsAt ? "map" : "results";
  const investigation = mapAt >= 0 ? messages[mapAt] : null;
  const latest = resultsAt >= 0 ? messages[resultsAt] : null;

  const send = useCallback(
    async (question) => {
      const text = question.trim();
      if (!text || busy) return;
      setDraft("");
      setBusyText("Querying the logs and checking the results…");
      setBusy(true);
      const history = conversation(messagesRef.current);
      setMessages((prev) => [...prev, { role: "user", text }]);
      const result = await ask(text, { day: dayRef.current || undefined, history });
      const ok = finish(result, ({ data, isMock }) => ({ role: "agent", data, isMock }));
      // By now the question is counted, so the answer's index (its speech id) is the count.
      if (ok && autoSpeakRef.current) speak(briefingText(result.data), countRef.current);
    },
    [busy, finish]
  );

  const runInvestigation = useCallback(
    async (chosen) => {
      if (busy) return;
      const target = typeof chosen === "string" ? chosen : dayRef.current;
      if (target) setDay(target);
      setBusyText("Hunting through the day for a compromised machine…");
      setBusy(true);
      setMessages((prev) => [
        ...prev,
        { role: "user", text: `Investigate${target ? ` ${dayLabel(target)}` : ""}: is there an attacker in these logs?` },
      ]);
      const result = await investigate(target || undefined);
      const ok = finish(result, ({ data }) => ({ role: "investigation", data }));
      if (ok && autoSpeakRef.current) {
        const { headline, summary, actions } = result.data;
        speak(briefingText({ answer: `${headline} ${summary}`, next_steps: actions }), countRef.current);
      }
    },
    [busy, finish]
  );

  const runScan = useCallback(async () => {
    if (busy) return;
    setBusyText("Checking every day of logins for a computer far outside normal…");
    setBusy(true);
    setMessages((prev) => [...prev, { role: "user", text: "Scan every day for signs of an attacker." }]);
    const result = await scan();
    if (finish(result, ({ data }) => ({ role: "scan", data }))) {
      // Point the day picker at the day that stands out most, ready to investigate.
      const worst = result.data.days
        .filter((d) => d.suspects.length)
        .sort((a, b) => (b.suspects[0].times_normal || 0) - (a.suspects[0].times_normal || 0))[0];
      if (worst) setDay(worst.day);
    }
  }, [busy, finish]);

  const { listening, interim, error: voiceError, start, stop } = useVoice({ onFinal: send });

  const clearConversation = useCallback(() => {
    stopSpeaking();
    setMessages([]);
    try {
      localStorage.removeItem(HISTORY_KEY);
    } catch {
      /* nothing stored */
    }
  }, []);

  // Keep the conversation only if the user asked for that; otherwise wipe any copy.
  useEffect(() => {
    try {
      if (settings.saveHistory) {
        localStorage.setItem(HISTORY_KEY, JSON.stringify(messages));
      } else {
        localStorage.removeItem(HISTORY_KEY);
      }
    } catch {
      /* storage blocked or full: history stays in memory */
    }
  }, [messages, settings.saveHistory]);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages, busy]);

  // Seconds counter while the agents work, so a 10-second wait reads as progress.
  useEffect(() => {
    if (!busy) return;
    const started = Date.now();
    const timer = setInterval(() => setElapsed(Math.floor((Date.now() - started) / 1000)), 500);
    return () => {
      clearInterval(timer);
      setElapsed(0);
    };
  }, [busy]);

  // The days of data on offer; start on the most recent one.
  useEffect(() => {
    if (!online) return;
    getDays().then((list) => {
      setDays(list);
      setDay((current) => current || list.at(-1)?.day || "");
    });
  }, [online]);

  useEffect(() => {
    let alive = true;
    const check = () => backendIsUp().then((up) => alive && setOnline(up));
    check();
    const timer = setInterval(check, 20000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, []);

  // "/" jumps to the question box from anywhere.
  useEffect(() => {
    const onKey = (e) => {
      const typing = ["INPUT", "TEXTAREA"].includes(document.activeElement?.tagName);
      if (e.key === "/" && !typing) {
        e.preventDefault();
        inputRef.current?.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  const closeSettings = useCallback(() => setSettingsOpen(false), []);
  const showMap = side === "map" && investigation;
  const showsRows = latest && !latest.data.timeline.length && latest.data.rows.length;
  const resultsTitle = showsRows ? "Query results" : "Attacker timeline";
  // After a scan and before anything else, say how to get from the scan to a map.
  const scanHint = scanAt > Math.max(mapAt, resultsAt);

  return (
    <MaskProvider value={maskFor(settings.maskNames)}>
      <div className="app">
        <header className="header">
          <div className="header__left">
            <span
              className={`status ${online ? "status--up" : online === false ? "status--down" : ""}`}
              title="LANL cyber-security events in ClickHouse"
            >
              <span className="status__dot" aria-hidden="true" />
              {online === null ? "Checking…" : online ? "Live data" : "Backend offline"}
            </span>
            {days.length > 1 && (
              <label className="daypick">
                Day
                <select className="select" value={day} onChange={(e) => setDay(e.target.value)}>
                  {days.map((d) => (
                    <option key={d.day} value={d.day}>{dayLabel(d.day)}</option>
                  ))}
                </select>
              </label>
            )}
            {settings.maskNames && <span className="chip">Names masked</span>}
          </div>

          <div className="brand">
            <span className={`brand__mark ${busy ? "is-busy" : ""}`} aria-hidden="true">
              <i /><i /><i /><i /><i />
            </span>
            <div>
              <h1 className="brand__name">LogWhisperer</h1>
              <p className="brand__tag">Talk to your security logs</p>
            </div>
          </div>

          <div className="header__right">
            {days.length > 1 && (
              <button className="btn btn--small btn--accent" onClick={runScan} disabled={busy}>
                Scan all days
              </button>
            )}
            <button className="btn btn--small btn--accent" onClick={runInvestigation} disabled={busy}>
              Investigate{day ? ` ${dayLabel(day)}` : ""}
            </button>
            <button className="btn btn--small" onClick={clearConversation} disabled={!messages.length || busy}>
              New chat
            </button>
            <div className="header__menu">
              <button
                className="btn btn--small"
                onClick={() => setSettingsOpen((v) => !v)}
                aria-expanded={settingsOpen}
              >
                Settings
              </button>
              {settingsOpen && (
                <Settings
                  settings={settings}
                  update={updateSettings}
                  onClearHistory={clearConversation}
                  onClose={closeSettings}
                />
              )}
            </div>
          </div>
        </header>

        <main className="grid">
          <section className="panel panel--chat">
            <div className="chat" ref={scrollRef}>
              {messages.length === 0 && (
                <div className="empty">
                  <span className="empty__glow" aria-hidden="true" />
                  <p className="empty__lead">Find the attacker, or ask the logs a question.</p>
                  <p className="empty__sub">
                    {days.length > 1
                      ? `Scan all ${days.length} days with no hints, investigate one, or hold the mic and ask.`
                      : "Investigate hunts through the logs with no hints. Or hold the mic and ask."}
                  </p>
                  <div className="empty__actions">
                    {days.length > 1 && (
                      <button className="btn btn--send btn--hero" onClick={runScan} disabled={busy}>
                        Scan all {days.length} days
                      </button>
                    )}
                    <button
                      className={`btn btn--hero ${days.length > 1 ? "btn--accent" : "btn--send"}`}
                      onClick={runInvestigation}
                      disabled={busy}
                    >
                      Investigate{day ? ` ${dayLabel(day)}` : ""}
                    </button>
                  </div>
                  <div className="empty__chips">
                    {DEMO_QUESTIONS.map((q) => (
                      <button key={q} className="chip chip--demo" onClick={() => send(q)}>
                        {q}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {messages.map((msg, i) =>
                msg.role === "user" ? (
                  <div key={i} className="bubble bubble--user">
                    {maskFor(settings.maskNames)(msg.text)}
                  </div>
                ) : msg.role === "error" ? (
                  <div key={i} className="bubble bubble--agent bubble--error" role="alert">
                    {msg.text}
                  </div>
                ) : msg.role === "scan" ? (
                  <Scan key={i} data={msg.data} onInvestigate={runInvestigation} busy={busy} />
                ) : msg.role === "investigation" ? (
                  <Investigation key={i} id={i} data={msg.data} />
                ) : (
                  <Answer key={i} id={i} data={msg.data} isMock={msg.isMock} />
                )
              )}

              {busy && (
                <div className="bubble bubble--agent thinking" role="status">
                  <div className="thinking__row">
                    <span className="dots"><i /><i /><i /></span>
                    {busyText}
                    <span className="thinking__time">{elapsed}s</span>
                  </div>
                  <div className="skeleton" aria-hidden="true"><i /><i /><i /></div>
                </div>
              )}
            </div>

            {voiceError && <p className="hint hint--warn composer__hint">{voiceError}</p>}

            {locked && (
              <form
                className="composer composer--lock"
                onSubmit={(e) => {
                  e.preventDefault();
                  setPasscode(new FormData(e.target).get("passcode").trim());
                  setLocked(false);
                }}
              >
                <input className="composer__input" name="passcode" type="password"
                       placeholder="Passcode for this demo" autoFocus required />
                <button className="btn btn--send" type="submit">Unlock</button>
              </form>
            )}

            <form
              className="composer"
              onSubmit={(e) => {
                e.preventDefault();
                send(draft);
              }}
            >
              <input
                ref={inputRef}
                className="composer__input"
                value={listening && interim ? interim : draft}
                onChange={(e) => setDraft(e.target.value)}
                placeholder="Ask in plain English…  (press / to focus)"
                disabled={busy}
              />
              <PushToTalk listening={listening} start={start} stop={stop} disabled={busy} />
              <button className="btn btn--send" type="submit" disabled={busy || !draft.trim()}>
                Send
              </button>
            </form>
          </section>

          <aside className="panel panel--side">
            <h2 className="panel__title panel__title--tabs">
              {investigation && latest ? (
                <>
                  <button className={showMap ? "is-on" : ""} onClick={() => setSidePick({ view: "map", at: messages.length })}>
                    Attack map{investigation.data.day ? ` · ${dayLabel(investigation.data.day)}` : ""}
                  </button>
                  <button className={showMap ? "" : "is-on"} onClick={() => setSidePick({ view: "results", at: messages.length })}>
                    {resultsTitle}
                  </button>
                </>
              ) : showMap ? (
                `Attack map${investigation.data.day ? ` · ${dayLabel(investigation.data.day)}` : ""}`
              ) : (
                resultsTitle
              )}
            </h2>
            {showMap ? (
              <InvestigationPanel key={mapAt} data={investigation.data} onScan={days.length > 1 ? runScan : null} />
            ) : scanHint ? (
              <div className="panel__body">
                <p className="hint">
                  The attack map appears when you investigate a day. Days marked in red have a
                  suspect: click <strong>Investigate</strong> on one of them.
                </p>
              </div>
            ) : (
              <Timeline key={resultsAt} timeline={latest?.data?.timeline} rows={latest?.data?.rows} />
            )}
          </aside>
        </main>
      </div>
    </MaskProvider>
  );
}
