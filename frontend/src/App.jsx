import { useCallback, useEffect, useRef, useState } from "react";
import { ask, backendIsUp, investigate } from "./api.js";
import { useVoice } from "./useVoice.js";
import { HISTORY_KEY, MaskProvider, maskFor, useSettings } from "./settings.js";
import { briefingText, setPreferredVoice, speak, stopSpeaking } from "./speech.js";
import Answer from "./components/Answer.jsx";
import Timeline from "./components/Timeline.jsx";
import PushToTalk from "./components/PushToTalk.jsx";
import Settings from "./components/Settings.jsx";
import Investigation from "./components/Investigation.jsx";
import InvestigationPanel from "./components/InvestigationPanel.jsx";
import "./App.css";

const DEMO_QUESTIONS = [
  "Which accounts logged into the most different computers yesterday?",
  "What did computer C17693 do yesterday, in time order?",
  "Were there any failed login bursts overnight?",
];

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
  const scrollRef = useRef(null);
  const inputRef = useRef(null);
  const countRef = useRef(messages.length);
  const autoSpeakRef = useRef(settings.autoSpeak);

  useEffect(() => {
    countRef.current = messages.length;
    autoSpeakRef.current = settings.autoSpeak;
  }, [messages.length, settings.autoSpeak]);

  useEffect(() => setPreferredVoice(settings.voice), [settings.voice]);

  // The newest answer drives the right-hand panel.
  const latest = [...messages]
    .reverse()
    .find((m) => m.role === "agent" || m.role === "investigation");

  const send = useCallback(
    async (question) => {
      const text = question.trim();
      if (!text || busy) return;
      setDraft("");
      setBusyText("Querying the logs and checking the results…");
      setBusy(true);
      setMessages((prev) => [...prev, { role: "user", text }]);
      const { data, isMock, error } = await ask(text);
      setMessages((prev) => [
        ...prev,
        error ? { role: "error", text: error } : { role: "agent", data, isMock },
      ]);
      setBusy(false);
      // By now the question is counted, so the answer's index (its speech id) is the count.
      if (!error && autoSpeakRef.current) speak(briefingText(data), countRef.current);
    },
    [busy]
  );

  const runInvestigation = useCallback(async () => {
    if (busy) return;
    setBusyText("Hunting through the whole day for a compromised machine…");
    setBusy(true);
    setMessages((prev) => [...prev, { role: "user", text: "Investigate: is there an attacker in these logs?" }]);
    const { data, error } = await investigate();
    setMessages((prev) => [
      ...prev,
      error ? { role: "error", text: error } : { role: "investigation", data },
    ]);
    setBusy(false);
    if (!error && autoSpeakRef.current) {
      speak(
        briefingText({ answer: `${data.headline} ${data.summary}`, next_steps: data.actions }),
        countRef.current
      );
    }
  }, [busy]);

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
  const investigated = latest?.role === "investigation";
  const showsRows =
    latest && !investigated && !latest.data.timeline.length && latest.data.rows.length;

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
            <button className="btn btn--small btn--accent" onClick={runInvestigation} disabled={busy}>
              Investigate
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
                    Investigate hunts through the whole day with no hints. Or hold the mic and ask.
                  </p>
                  <button className="btn btn--send btn--hero" onClick={runInvestigation} disabled={busy}>
                    Run an investigation
                  </button>
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
            <h2 className="panel__title">
              {investigated ? "Attack map" : showsRows ? "Query results" : "Attacker timeline"}
            </h2>
            {investigated ? (
              <InvestigationPanel key={messages.length} data={latest.data} />
            ) : (
              <Timeline key={messages.length} timeline={latest?.data?.timeline} rows={latest?.data?.rows} />
            )}
          </aside>
        </main>
      </div>
    </MaskProvider>
  );
}
