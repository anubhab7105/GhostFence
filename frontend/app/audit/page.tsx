"use client";

import { useState } from "react";

const GATEWAY = process.env.NEXT_PUBLIC_GATEWAY_URL || "http://localhost:8000";

export default function AuditPage() {
  const [apiKey, setApiKey] = useState("dev-admin-key");
  const [verifyResult, setVerifyResult] = useState<any>(null);
  const [tamperSeq, setTamperSeq] = useState("1");
  const [tamperReason, setTamperReason] = useState("tampered");
  const [tamperResult, setTamperResult] = useState<any>(null);

  async function verify() {
    const resp = await fetch(`${GATEWAY}/v1/audit/verify`, {
      method: "POST",
      headers: { "X-API-Key": apiKey },
    });
    setVerifyResult(await resp.json());
  }

  async function tamper() {
    const resp = await fetch(`${GATEWAY}/v1/audit/tamper-demo?sequence=${tamperSeq}&new_reason=${encodeURIComponent(tamperReason)}`, {
      method: "POST",
      headers: { "X-API-Key": apiKey },
    });
    setTamperResult(await resp.json());
  }

  return (
    <main style={{ padding: 24 }}>
      <h1>Audit Logs</h1>
      <input value={apiKey} onChange={(e) => setApiKey(e.target.value)} placeholder="API key" />
      <button onClick={verify}>Verify chain</button>
      <pre>{JSON.stringify(verifyResult, null, 2)}</pre>
      <h2>Tamper demo</h2>
      <input value={tamperSeq} onChange={(e) => setTamperSeq(e.target.value)} placeholder="sequence" />
      <input value={tamperReason} onChange={(e) => setTamperReason(e.target.value)} placeholder="new reason" />
      <button onClick={tamper}>Tamper</button>
      <pre>{JSON.stringify(tamperResult, null, 2)}</pre>
    </main>
  );
}