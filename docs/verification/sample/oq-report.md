# Community verification report

Evidence that supports a customer's own records. Designed to support GLP / 21 CFR Part 11 / EU GMP Annex 11 workflows.

- Generated at: 2026-10-18T21:19:11+00:00
- Package: mcp-glp-audit-proxy 0.1.0
- Python: 3.12.3
- OS: Linux-6.12.94+-x86_64-with-glibc2.39
- Git sha: 50da88e4762b1ece674c95b832672330939a17a9
- Tests: 63 passed, 0 failed, 63 total
- Requirements: 51 community, 23 out of scope (Pro), 3 customer responsibility, 5 gap
- Line coverage: 69.7

## Cases

| Test | Expected | Actual | Time |
|---|---|---|---|
| `tests/test_approval.py::test_write_is_held_until_a_different_approver_accepts` | pass | pass | 0.126 |
| `tests/test_approval.py::test_reviewed_and_rejected_do_not_authorise` | pass | pass | 0.115 |
| `tests/test_approval.py::test_operator_cannot_approve_and_cannot_self_approve` | pass | pass | 0.112 |
| `tests/test_approval.py::test_changed_arguments_do_not_match_the_approval` | pass | pass | 0.114 |
| `tests/test_approval.py::test_expired_approval_is_refused` | pass | pass | 0.113 |
| `tests/test_chain.py::test_rfc8785_vectors_match_pinned_implementation` | pass | pass | 0.001 |
| `tests/test_chain.py::test_chain_links_and_matches_schema` | pass | pass | 0.086 |
| `tests/test_docs.py::test_readme_is_ascii_and_states_the_boundary` | pass | pass | 0.015 |
| `tests/test_docs.py::test_source_has_no_pro_implementations` | pass | pass | 0.003 |
| `tests/test_docs.py::test_registry_metadata_matches_the_package` | pass | pass | 0.001 |
| `tests/test_export.py::test_entries_match_the_published_schema` | pass | pass | 0.156 |
| `tests/test_export.py::test_qa_can_search_and_export_operator_cannot` | pass | pass | 0.137 |
| `tests/test_export.py::test_export_path_cannot_escape` | pass | pass | 0.110 |
| `tests/test_export.py::test_verify_cli_exports_only_a_valid_chain` | pass | pass | 0.115 |
| `tests/test_fail_closed.py::test_unhealthy_store_does_not_forward` | pass | pass | 0.107 |
| `tests/test_fail_closed.py::test_append_failure_hides_upstream_result` | pass | pass | 0.106 |
| `tests/test_fail_closed.py::test_denied_call_is_logged_and_not_forwarded` | pass | pass | 0.112 |
| `tests/test_fail_closed.py::test_failed_upstream_call_is_logged` | pass | pass | 0.108 |
| `tests/test_fail_closed.py::test_tool_is_error_is_logged_as_failed` | pass | pass | 0.107 |
| `tests/test_fail_closed.py::test_tampered_chain_does_not_forward` | pass | pass | 0.104 |
| `tests/test_fail_closed.py::test_store_refuses_disposal` | pass | pass | 0.104 |
| `tests/test_faults.py::test_fsync_enospc_latches_the_proxy` | pass | pass | 0.103 |
| `tests/test_faults.py::test_eio_and_permission_errors_are_store_errors` | pass | pass | 0.004 |
| `tests/test_faults.py::test_broken_chain_latches_and_does_not_retry` | pass | pass | 0.102 |
| `tests/test_faults.py::test_partial_line_is_detected_and_blocks_the_next_append` | pass | pass | 0.004 |
| `tests/test_faults.py::test_insert_duplicate_and_tail_shapes` | pass | pass | 0.005 |
| `tests/test_faults.py::test_parallel_appends_stay_one_record_per_line` | pass | pass | 0.106 |
| `tests/test_faults.py::test_backwards_clock_is_stored_as_given` | pass | pass | 0.106 |
| `tests/test_faults.py::test_upstream_crash_is_logged_and_does_not_consume_approval` | pass | pass | 0.011 |
| `tests/test_faults.py::test_upstream_timeout` | pass | pass | 2.303 |
| `tests/test_faults.py::test_transport_failure_keeps_the_approval` | pass | pass | 0.121 |
| `tests/test_features.py::test_licence_is_local_and_does_not_phone_home` | pass | pass | 0.054 |
| `tests/test_features.py::test_community_entry_points_only` | pass | pass | 0.020 |
| `tests/test_features.py::test_remote_transport_is_tls_1_3` | pass | pass | 0.016 |
| `tests/test_features.py::test_sdk_floor_rejects_the_advisory_range` | pass | pass | 0.001 |
| `tests/test_limits.py::test_name_tricks_fail_closed` | pass | pass | 0.002 |
| `tests/test_limits.py::test_secrets_are_stripped_from_meta_and_the_log` | pass | pass | 0.108 |
| `tests/test_limits.py::test_malformed_and_oversized_messages_are_not_forwarded` | pass | pass | 0.110 |
| `tests/test_policy.py::test_allowlist_and_denylist` | pass | pass | 0.109 |
| `tests/test_policy.py::test_empty_allow_denies_upstream` | pass | pass | 0.105 |
| `tests/test_policy.py::test_write_requires_reason` | pass | pass | 0.108 |
| `tests/test_policy.py::test_qa_and_admin_cannot_call_upstream` | pass | pass | 0.112 |
| `tests/test_policy.py::test_admin_policy_change_is_audited_and_replayed` | pass | pass | 0.114 |
| `tests/test_policy.py::test_retention_floor_and_swiss_default` | pass | pass | 0.001 |
| `tests/test_properties.py::test_canonical_form_is_stable` | pass | pass | 0.165 |
| `tests/test_properties.py::test_sealed_lines_verify_and_a_byte_flip_does_not` | pass | pass | 0.052 |
| `tests/test_protocol.py::test_legacy_host_and_legacy_upstream_record_session_ids` | pass | pass | 0.117 |
| `tests/test_protocol.py::test_modern_host_has_no_session_and_ignores_a_session_hint` | pass | pass | 0.113 |
| `tests/test_protocol.py::test_modern_host_against_legacy_upstream_falls_back` | pass | pass | 0.107 |
| `tests/test_protocol.py::test_resources_and_prompts_are_logged` | pass | pass | 0.118 |
| `tests/test_protocol.py::test_stdio_subprocess_upstream_does_not_inherit_parent_secrets` | pass | pass | 0.074 |
| `tests/test_protocol.py::test_proxy_stdio_speaks_discover` | pass | pass | 0.596 |
| `tests/test_reconciliation_sop.py::test_sop_snippet_appends_a_verifiable_entry` | pass | pass | 0.010 |
| `tests/test_reconciliation_sop.py::test_sop_is_linked` | pass | pass | 0.001 |
| `tests/test_rtm.py::test_community_rows_name_real_tests` | pass | pass | 0.090 |
| `tests/test_rtm.py::test_verification_docs_avoid_banned_words` | pass | pass | 0.001 |
| `tests/test_sample_report.py::test_sample_report_hash_and_wording` | pass | pass | 0.001 |
| `tests/test_tamper.py::test_valid_chain` | pass | pass | 0.008 |
| `tests/test_tamper.py::test_modified_payload_is_detected` | pass | pass | 0.007 |
| `tests/test_tamper.py::test_whitespace_is_detected` | pass | pass | 0.006 |
| `tests/test_tamper.py::test_deleted_line_is_a_gap` | pass | pass | 0.007 |
| `tests/test_tamper.py::test_reordered_lines_are_detected` | pass | pass | 0.008 |
| `tests/test_tamper.py::test_unknown_hash_algo_is_rejected` | pass | pass | 0.009 |

## Dependencies

| Name | Version | SHA-256 |
|---|---|---|
| mcp | 2.3.0 | `cf7213be0f51c210ba49f5c5d315b6643fb650521f05d0bea52bbd39b2bc634b` |
| rfc8785 | 0.1.4 | `476c34e39dbf263f3c2ec4911785663d27f921b23d66a895036067bb4f0676b9` |
| pytest | 9.1.1 | `ddb0d1caa9fe73f73cdbdbb483e77d4efcd0ee74da1a74e949bfe8494b81362e` |
| hypothesis | 6.170.1 | `81b1cb0e8096b52d60aaeb205e7e0d1bc5afa9c88676dcb9d5feebb29288c26e` |
| jsonschema | 4.26.0 | `633d1c647f2bf083d30541dce1791acc3f62ec615eee92181f7089435e70fcec` |
| PyYAML | 6.0.1 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

Report SHA-256: `eccd169746ad542f32a0193a9602e46477914551aa65bf6d4712e6266b4f2ab1`
