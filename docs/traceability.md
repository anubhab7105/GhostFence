# Traceability Matrix

## Functional Requirements FR-1 to FR-78

| FR | Status | Implementing file/function | Tests |
|---|---|---|---|
| FR-1 | Done | backend/app/gateway/executor.py execute_tool | test_roundtrip |
| FR-2 | Done | backend/app/schemas/common.py Decision; pipeline.py | test_roundtrip |
| FR-3 | Done | sdk/python/ghostfence/client.py GhostFenceClient.execute | (manual) |
| FR-4 | Done | backend/app/schemas/api.py ExecuteRequest | test_roundtrip |
| FR-5 | Done | backend/app/gateway/pipeline.py jsonschema_validate | (unit via pipeline) |
| FR-6 | Done | backend/app/main.py /v1/execute | test_roundtrip |
| FR-7 | Partial | backend/app/api/inspect.py inspect_content | (manual) |
| FR-8 | Partial | backend/app/api/inspect.py inspect_content | (manual) |
| FR-9 | Done | backend/app/api/inspect.py InspectResponse | (manual) |
| FR-10 | Done | backend/app/gateway/runs.py set_tainted | test_roundtrip (indirect) |
| FR-11 | Done | backend/app/policy_engine/engine.py (detection advisory only) | test_policy_rules |
| FR-12 | Done | backend/app/policy_engine/engine.py (default block) | test_policy_rules |
| FR-13 | Done | backend/app/schemas/policy.py Policy | test_schemas |
| FR-14 | Done | backend/app/schemas/policy.py approval_required | test_schemas |
| FR-15 | Done | backend/app/policy_engine/engine.py version = content hash | test_roundtrip |
| FR-16 | Done | policies/example.yaml | test_schemas |
| FR-17 | Partial | backend/app/api/policies.py (read-only) | (manual) |
| FR-18 | Done | backend/app/schemas/resources.py ResourceCatalogue | test_schemas |
| FR-19 | Done | backend/app/data_protection/scanner.py scan_outbound | test_egress |
| FR-20 | Done | backend/app/policy_engine/engine.py _destination_allowed | test_egress |
| FR-21 | Done | backend/app/gateway/pipeline.py decision records | test_roundtrip |
| FR-22 | Not done | - | - |
| FR-23 | Not done | - | - |
| FR-24 | Not done | - | - |
| FR-25 | Done | backend/app/gateway/runs.py update_sensitivity_high_water | (manual) |
| FR-26 | Deferred | backend/app/api/approvals.py | (manual) |
| FR-27 | Deferred | backend/app/api/approvals.py decide | (manual) |
| FR-28 | Done | backend/app/policy_engine/engine.py taint check | test_policy_rules |
| FR-29 | Done | backend/app/audit/service.py append_entry | test_audit |
| FR-30 | Done | backend/app/attack_lab/runner.py cross_check | test_cross_check |
| FR-31 | Deferred | backend/app/api/approvals.py | (manual) |
| FR-32 | Deferred | backend/app/api/approvals.py | (manual) |
| FR-33 | Done | backend/app/audit/service.py redacted_excerpt | test_audit |
| FR-34 | Done | attack-lab/sample_data | (manual) |
| FR-35 | Done | attack-lab/scenarios | (manual) |
| FR-36 | Done | backend/app/attack_lab/runner.py protected/unprotected | test_reliability (smoke) |
| FR-37 | Partial | backend/app/api/attacks.py replay | (manual) |
| FR-38 | Partial | backend/app/attack_lab/runner.py summary | (manual) |
| FR-39 | Done | attack-lab/scenarios/*.yaml | test_schemas |
| FR-40 | Partial | frontend/app/* pages | (build) |
| FR-41 | Partial | frontend/app/page.tsx | (build) |
| FR-42 | Not done | - | - |
| FR-43 | Partial | frontend (SSE not wired) | - |
| FR-44 | Done | backend/app/api/runs.py create_run_endpoint | test_roundtrip |
| FR-45 | Done | backend/app/api/runs.py close_run_endpoint | (manual) |
| FR-46 | Done | backend/app/core/security.py issue/verify_run_token | test_roundtrip |
| FR-47 | Partial | backend/app/gateway/runs.py create_run scope | (manual) |
| FR-48 | Done | backend/app/gateway/runs.py create_run TTL | test_roundtrip |
| FR-49 | Done | backend/app/gateway/pipeline.py denial threshold | (manual) |
| FR-50 | Done | attack-lab/scenarios/*.yaml | test_schemas |
| FR-51 | Done | backend/app/attack_lab/runner.py modes | (manual) |
| FR-52 | Partial | scripted agent in runner.py | (manual) |
| FR-53 | Not done | - | - |
| FR-54 | Partial | backend/app/api/attacks.py replay | (manual) |
| FR-55 | Partial | backend/app/attack_lab/runner.py summary | (manual) |
| FR-56 | Done | s1/s2/s3 scenarios | (manual) |
| FR-57 | Not done | S4 not implemented | - |
| FR-58 | Not done | benign suite not implemented | - |
| FR-59 | Partial | backend/app/checkpointer/service.py | (manual) |
| FR-60 | Not done | LangChain adapter not implemented | - |
| FR-61 | Partial | frontend plain-text rendering | (build) |
| FR-62 | Partial | backend/app/api/llm.py | (manual) |
| FR-63 | Done | backend/app/schemas/resources.py classify | test_schemas |
| FR-64 | Done | backend/app/gateway/pipeline.py allow_with_flag matrix | test_policy_rules |
| FR-65 | Done | backend/app/gateway/egress.py | test_egress |
| FR-66 | Partial | backend/app/gateway/pipeline.py partial_transmission | (manual) |
| FR-67 | Deferred | backend/app/api/approvals.py | (manual) |
| FR-68 | Not done | HMAC-bound approvals not implemented | - |
| FR-69 | Done | backend/app/audit/recovery.py | test_audit |
| FR-70 | Done | docs/runbook.md | (doc) |
| FR-71 | Partial | scripts/backup.sh, restore.sh | test_restore_script |
| FR-72 | Partial | backend/app/main.py /v1/stream | (manual) |
| FR-73 | Partial | backend/app/api/llm.py retention/training | (manual) |
| FR-74 | Done | backend/app/gateway/pipeline.py risk-v1 | test_roundtrip (indirect) |
| FR-75 | Not done | behavior monitoring not implemented | - |
| FR-76 | Partial | backend/app/gateway/pipeline.py provenance | (manual) |
| FR-77 | Partial | backend/app/gateway/runs.py sensitivity high-water | (manual) |
| FR-78 | Partial | tests/test_egress, test_normalization, etc. | (tests) |

## P1 items

| P1 item | Exists? |
|---|---|
| Approval workflow (dashboard page) | Partial (API + page missing) |
| Signed checkpoints | Partial (service) |
| Benign suite 30+ | No |
| Benchmark subset | Partial (bench runner) |
| S4 | No |
| Inspector sanitisation | Partial |
| LangChain adapter | No |