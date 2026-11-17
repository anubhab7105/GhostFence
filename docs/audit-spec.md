# Audit hash specification (D8)

- genesis_hash = SHA-256 of the ASCII string `ghostfence/audit/genesis/v1`
- domain_separator = ASCII `ghostfence/audit/entry/v1` followed by a NUL byte
- payload = entry fields excluding entry_hash, including previous_hash once as lowercase hex
- entry_hash = SHA-256(domain_separator || raw 32-byte previous_hash || RFC 8785 canonical UTF-8 JSON of payload)
- no floats anywhere; timestamps RFC 3339 UTC
- appends serialised via `SELECT ... FOR UPDATE` on a chain-head row

Genesis hash: `4febf9bd83efbb0c82bbe8cef0eb8aa3d69224b0f0086675fc198f32c1c396de`

## Worked test vector (Phase 2 will assert this)

Fixed inputs:

```json
{
  "agent_id": "invoice-agent",
  "decision": "allow",
  "evidence_hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
  "policy_version": "1.0",
  "previous_hash": "4febf9bd83efbb0c82bbe8cef0eb8aa3d69224b0f0086675fc198f32c1c396de",
  "reason_code": "allowed",
  "redacted_excerpt": null,
  "risk_score": 0,
  "sequence": 1,
  "session_id": "session-1",
  "timestamp": "2026-11-17T00:00:00Z",
  "tool_name": "read_file"
}
```

Canonical payload bytes (UTF-8):

`7b226167656e745f6964223a22696e766f6963652d6167656e74222c226465636973696f6e223a22616c6c6f77222c2265766964656e63655f686173686573223a5b2265336230633434323938666331633134396166626634633839393666623932343237616534316534363439623933346361343935393931623738353262383535225d2c22706f6c6963795f76657273696f6e223a22312e30222c2270726576696f75735f68617368223a2234666562663962643833656662623063383262626538636566306562386161336436393232346230663030383636373566633139386633326331633339366465222c22726561736f6e5f636f6465223a22616c6c6f776564222c2272656461637465645f65786365727074223a6e756c6c2c227269736b5f73636f7265223a302c2273657175656e6365223a312c2273657373696f6e5f6964223a2273657373696f6e2d31222c2274696d657374616d70223a22323032362d31312d31375430303a30303a30305a222c22746f6f6c5f6e616d65223a22726561645f66696c65227d`

Expected entry_hash: `69305a8fc5a7ab3e87ead0ee020ae5d5638fd036a4a4dc57e294603747a32594`