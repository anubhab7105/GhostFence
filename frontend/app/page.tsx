"use client";

import { useState } from "react";

const GATEWAY = process.env.NEXT_PUBLIC_GATEWAY_URL || "http://localhost:8000";

export default function ReplayPage() {
  const [apiKey, setApiKey] = useState("dev-agent-key");
  const [scenario, setScenario] = useState("s1");
  const [mode, setMode] = useState("protected");
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState("");

  async function run() {
    setError("");
    try {
      const runResp = await fetch(`${GATEWAY}/v1/runs`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-API-Key": apiKey },
        body: JSON.stringify({ agent_id: "invoice-agent", task: "demo", mode }),
      });
      if (!runResp.ok) throw new Error(await runResp.text());
      const run = await runResp.json();
      const attackResp = await fetch(`${GATEWAY}/v1/attacks/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-API-Key": apiKey },
        body: JSON.stringify({ scenario_id: scenario, mode }),
      });
      if (!attackResp.ok) throw new Error(await attackResp.text());
      setResult(await attackResp.json());
    } catch (e: any) {
      setError(String(e));
    }
  }

  return (
    <main style={{ padding: 24 }}>
      <h1>GhostFence Replay</h1>
      <div>
        <input value={apiKey} onChange={(e) => setApiKey(e.target.value)} placeholder="API key" />
        <select value={scenario} onChange={(e) => setScenario(e.target.value)}>
          <option value="s1">S1</option>
          <option value="s2">S2</option>
          <option value="s3">S3</option>
        </select>
        <select value={mode} onChange={(e) => setMode(e.target.value)}>
          <option value="protected">protected</option>
          <option value="unprotected">unprotected</option>
        </select>
        <button onClick={run}>Run scenario</button>
      </div>
      {error && <pre>{error}</pre>}
      {result && <pre>{JSON.stringify(result, null, 2)}</pre>}
    </main>
  );
}