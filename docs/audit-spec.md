# Audit hash specification (D8)

- genesis_hash = SHA-256 of the ASCII string `ghostfence/audit/genesis/v1`
- domain_separator = ASCII `ghostfence/audit/entry/v1` followed by a NUL byte
- payload = entry fields excluding entry_hash, including previous_hash once as lowercase hex
- entry_hash = SHA-256(domain_separator || raw 32-byte previous_hash || RFC 8785 canonical UTF-8 JSON of payload)
- no floats anywhere; timestamps RFC 3339 UTC
- appends serialised via `SELECT ... FOR UPDATE` on a chain-head row

Genesis hash: `4febf9bd83efbb0c82bbe8cef0eb8aa3d69224b0f0086675fc198f32c1c396de`