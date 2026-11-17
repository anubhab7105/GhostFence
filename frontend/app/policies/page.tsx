"use client";

import { useEffect, useState } from "react";

const GATEWAY = process.env.NEXT_PUBLIC_GATEWAY_URL || "http://localhost:8000";

export default function PoliciesPage() {
  const [apiKey, setApiKey] = useState("dev-admin-key");
  const [data, setData] = useState<any>(null);

  async function load() {
    const resp = await fetch(`${GATEWAY}/v1/policies`, {
      headers: { "X-API-Key": apiKey },
    });
    setData(await resp.json());
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <main style={{ padding: 24 }}>
      <h1>Policies</h1>
      <input value={apiKey} onChange={(e) => setApiKey(e.target.value)} placeholder="API key" />
      <button onClick={load}>Reload</button>
      <pre>{JSON.stringify(data, null, 2)}</pre>
    </main>
  );
}