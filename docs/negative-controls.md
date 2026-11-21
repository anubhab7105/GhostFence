# Negative Controls

1. Suffix-only domain matching — test_normalization.py::test_suffix_domain_match_is_not_suffix_only — command: `sed -i 's/return host == allowed or host.endswith("." + allowed)/return host.endswith(allowed)/' app/policy_engine/normalization.py`
2. Private/metadata IP blocking — test_normalization.py::test_blocked_ips — command: replace ip_is_blocked conditions with `if False:`
3. DNS pinning — test_egress.py::test_pinning_uses_resolved_ip — command: replace pinned_url with url
4. Trifecta rule — test_policy_rules.py::test_trifecta_blocks_sensitive_tool_when_tainted — command: replace taint condition with `if False and ...`
5. Unknown resource → restricted — test_schemas.py::test_resources_validates_and_fail_closed and test_policy_rules.py::test_unknown_resource_restricted — command: replace `return Sensitivity.restricted` with `return Sensitivity.public`
6. allow_with_flag impact matrix — test_policy_rules.py::test_allow_with_flag_matrix — command: replace require_approval with allow_with_flag
7. Unregistered tool block — test_policy_rules.py::test_unregistered_tool_blocked — command: replace unregistered block with allow
8. Hash chain verify — test_audit.py::test_modification_detected — command: disable entry_hash recomputation check
9. Sink-vs-decision cross-check — test_cross_check.py::test_sink_vs_decision_cross_check_mismatch — command: make cross_check always True