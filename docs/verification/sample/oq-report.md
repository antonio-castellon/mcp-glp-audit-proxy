# Community verification report

Evidence that supports a customer's own records. Designed to support GLP / 21 CFR Part 11 / EU GMP Annex 11 workflows.

- Generated at: 2026-10-21T13:09:43+00:00
- Package: mcp-glp-audit-proxy 0.2.0
- Python: 3.12.3
- OS: Linux-6.12.94+-x86_64-with-glibc2.39
- Git sha: 5d54ac4b7952389c3e4fcdcbc07e751888c7b7d4
- Tests: 123 passed, 0 failed, 123 total
- Requirements: 54 community, 23 out of scope (Pro), 3 customer responsibility, 4 gap
- Line coverage: 89.4

## Cases

| Test | Expected | Actual | Time |
|---|---|---|---|
| `tests/test_anchor.py::test_truncating_whole_lines_fails_verification` | pass | pass | 0.017 |
| `tests/test_anchor.py::test_consistent_truncation_of_log_and_head_is_a_residual_risk` | pass | pass | 0.011 |
| `tests/test_anchor.py::test_corrupt_or_missing_head_fails` | pass | pass | 0.011 |
| `tests/test_anchor.py::test_one_record_lag_is_recovered_not_a_false_alarm` | pass | pass | 0.024 |
| `tests/test_anchor.py::test_startup_disagreement_refuses_to_start` | pass | pass | 1.232 |
| `tests/test_anchor.py::test_settings_round_trip_and_clock_branches` | pass | pass | 0.002 |
| `tests/test_approval.py::test_write_is_held_until_a_different_approver_accepts` | pass | pass | 0.125 |
| `tests/test_approval.py::test_reviewed_and_rejected_do_not_authorise` | pass | pass | 0.196 |
| `tests/test_approval.py::test_legacy_reviewed_approval_still_verifies_and_does_not_authorise` | pass | pass | 0.143 |
| `tests/test_approval.py::test_operator_cannot_approve_and_cannot_self_approve` | pass | pass | 0.120 |
| `tests/test_approval.py::test_changed_arguments_do_not_match_the_approval` | pass | pass | 0.119 |
| `tests/test_approval.py::test_matching_approval_is_consumed_when_the_gate_is_turned_off` | pass | pass | 0.151 |
| `tests/test_approval.py::test_expired_approval_is_refused` | pass | pass | 0.120 |
| `tests/test_chain.py::test_rfc8785_vectors_match_pinned_implementation` | pass | pass | 0.001 |
| `tests/test_chain.py::test_chain_links_and_matches_schema` | pass | pass | 0.089 |
| `tests/test_docs.py::test_readme_is_ascii_and_states_the_boundary` | pass | pass | 0.022 |
| `tests/test_docs.py::test_source_has_no_pro_implementations` | pass | pass | 0.004 |
| `tests/test_docs.py::test_registry_metadata_matches_the_package` | pass | pass | 0.001 |
| `tests/test_docs.py::test_community_pro_table_is_filled` | pass | pass | 0.002 |
| `tests/test_export.py::test_entries_match_the_published_schema` | pass | pass | 0.160 |
| `tests/test_export.py::test_qa_can_search_and_export_operator_cannot` | pass | pass | 0.152 |
| `tests/test_export.py::test_export_path_cannot_escape` | pass | pass | 0.107 |
| `tests/test_export.py::test_verify_cli_exports_only_a_valid_chain` | pass | pass | 0.114 |
| `tests/test_fail_closed.py::test_unhealthy_store_does_not_forward` | pass | pass | 0.105 |
| `tests/test_fail_closed.py::test_append_failure_hides_upstream_result` | pass | pass | 0.105 |
| `tests/test_fail_closed.py::test_denied_call_is_logged_and_not_forwarded` | pass | pass | 0.111 |
| `tests/test_fail_closed.py::test_failed_upstream_call_is_logged` | pass | pass | 0.110 |
| `tests/test_fail_closed.py::test_tool_is_error_is_logged_as_failed` | pass | pass | 0.109 |
| `tests/test_fail_closed.py::test_tampered_chain_does_not_forward` | pass | pass | 0.104 |
| `tests/test_fail_closed.py::test_store_refuses_disposal` | pass | pass | 0.105 |
| `tests/test_faults.py::test_fsync_enospc_latches_the_proxy` | pass | pass | 0.106 |
| `tests/test_faults.py::test_eio_and_permission_errors_are_store_errors` | pass | pass | 0.004 |
| `tests/test_faults.py::test_broken_chain_latches_and_does_not_retry` | pass | pass | 0.104 |
| `tests/test_faults.py::test_partial_line_is_detected_and_blocks_the_next_append` | pass | pass | 0.009 |
| `tests/test_faults.py::test_insert_duplicate_and_tail_shapes` | pass | pass | 0.010 |
| `tests/test_faults.py::test_parallel_appends_stay_one_record_per_line` | pass | pass | 0.147 |
| `tests/test_faults.py::test_backwards_clock_is_stored_as_given` | pass | pass | 0.115 |
| `tests/test_faults.py::test_upstream_crash_is_logged_and_does_not_consume_approval` | pass | pass | 0.011 |
| `tests/test_faults.py::test_upstream_timeout` | pass | pass | 2.303 |
| `tests/test_faults.py::test_transport_failure_keeps_the_approval` | pass | pass | 0.127 |
| `tests/test_features.py::test_licence_is_local_and_does_not_phone_home` | pass | pass | 0.051 |
| `tests/test_features.py::test_community_entry_points_only` | pass | pass | 0.021 |
| `tests/test_features.py::test_remote_transport_is_tls_1_3` | pass | pass | 0.016 |
| `tests/test_features.py::test_sdk_floor_rejects_the_advisory_range` | pass | pass | 0.001 |
| `tests/test_flow_diagram.py::test_committed_picture_matches_the_renderer` | pass | pass | 0.002 |
| `tests/test_flow_diagram.py::test_readme_uses_the_absolute_picture_and_drops_the_ascii_fence` | pass | pass | 0.001 |
| `tests/test_framing.py::test_bounded_reader_stops_at_the_limit` | pass | pass | 0.001 |
| `tests/test_framing.py::test_bounded_reader_times_out` | pass | pass | 0.201 |
| `tests/test_framing.py::test_host_stream_without_a_newline_ends_the_session` | pass | pass | 1.153 |
| `tests/test_framing.py::test_upstream_stream_without_a_newline_is_refused` | pass | pass | 0.011 |
| `tests/test_hello_example.py::test_walkthrough_audits_and_detects_tamper` | pass | pass | 1.724 |
| `tests/test_hello_example.py::test_module_verify_subcommand` | pass | pass | 0.003 |
| `tests/test_hello_example.py::test_guides_point_at_the_audit_hello` | pass | pass | 0.001 |
| `tests/test_limits.py::test_name_tricks_fail_closed` | pass | pass | 0.002 |
| `tests/test_limits.py::test_secrets_are_stripped_from_meta_and_the_log` | pass | pass | 0.112 |
| `tests/test_limits.py::test_malformed_and_oversized_messages_are_not_forwarded` | pass | pass | 0.107 |
| `tests/test_manual_guides.py::test_readme_links_the_manuals` | pass | pass | 0.000 |
| `tests/test_manual_guides.py::test_guides_are_ascii_and_use_the_allowed_words` | pass | pass | 0.002 |
| `tests/test_manual_guides.py::test_proxy_configs_load_and_start` | pass | pass | 22.525 |
| `tests/test_manual_guides.py::test_licence_snippets_load` | pass | pass | 0.030 |
| `tests/test_manual_guides.py::test_client_snippets_use_real_proxy_args` | pass | pass | 0.002 |
| `tests/test_manual_guides.py::test_rpc_and_yaml_snippets_parse` | pass | pass | 0.007 |
| `tests/test_manual_guides.py::test_python_snippets_parse` | pass | pass | 0.003 |
| `tests/test_manual_guides.py::test_bash_flags_match_help` | pass | pass | 1.352 |
| `tests/test_manual_guides.py::test_dockerfile_matches_the_guide_and_has_no_port` | pass | pass | 0.001 |
| `tests/test_manual_guides.py::test_official_sdk_handshake` | pass | pass | 0.580 |
| `tests/test_manual_guides.py::test_airgap_wheel_builds_without_deps` | pass | pass | 7.582 |
| `tests/test_oq_runner.py::test_oq_report_happy_path` | pass | pass | 0.540 |
| `tests/test_oq_runner.py::test_oq_report_failing_test_path` | pass | pass | 0.512 |
| `tests/test_oq_runner.py::test_oq_report_module_entry` | pass | pass | 0.687 |
| `tests/test_oq_runner.py::test_oq_report_refuses_a_path_that_is_not_a_checkout` | pass | pass | 0.002 |
| `tests/test_oq_runner.py::test_oq_report_accepts_an_explicit_repo_root` | pass | pass | 0.517 |
| `tests/test_oq_runner.py::test_missing_checkout_is_a_clear_error` | pass | pass | 0.002 |
| `tests/test_oq_runner.py::test_both_oq_commands_are_documented` | pass | pass | 0.001 |
| `tests/test_oq_runner.py::test_coverage_percent_reads_the_requested_file` | pass | pass | 0.003 |
| `tests/test_plugins.py::test_defaults_build_the_community_plugins` | pass | pass | 0.054 |
| `tests/test_plugins.py::test_unknown_unlicensed_and_missing_plugins_refuse_startup` | pass | pass | 0.083 |
| `tests/test_plugins.py::test_selected_signer_and_reporter_are_used` | pass | pass | 0.044 |
| `tests/test_plugins.py::test_env_identity_is_the_default_and_other_auth_plugins_fail_closed` | pass | pass | 0.090 |
| `tests/test_plugins.py::test_text_export_and_unknown_format` | pass | pass | 0.116 |
| `tests/test_policy.py::test_allowlist_and_denylist` | pass | pass | 0.110 |
| `tests/test_policy.py::test_empty_allow_denies_upstream` | pass | pass | 0.109 |
| `tests/test_policy.py::test_write_requires_reason` | pass | pass | 0.113 |
| `tests/test_policy.py::test_qa_and_admin_cannot_call_upstream` | pass | pass | 0.117 |
| `tests/test_policy.py::test_admin_policy_change_is_audited_and_replayed` | pass | pass | 0.119 |
| `tests/test_policy.py::test_retention_floor_and_swiss_default` | pass | pass | 0.000 |
| `tests/test_properties.py::test_canonical_form_is_stable` | pass | pass | 0.189 |
| `tests/test_properties.py::test_sealed_lines_verify_and_a_byte_flip_does_not` | pass | pass | 0.070 |
| `tests/test_protocol.py::test_legacy_host_and_legacy_upstream_record_session_ids` | pass | pass | 0.127 |
| `tests/test_protocol.py::test_modern_host_has_no_session_and_ignores_a_session_hint` | pass | pass | 0.113 |
| `tests/test_protocol.py::test_modern_host_against_legacy_upstream_falls_back` | pass | pass | 0.108 |
| `tests/test_protocol.py::test_resources_and_prompts_are_logged` | pass | pass | 0.120 |
| `tests/test_protocol.py::test_stdio_subprocess_upstream_does_not_inherit_parent_secrets` | pass | pass | 0.078 |
| `tests/test_protocol.py::test_proxy_stdio_speaks_discover` | pass | pass | 1.136 |
| `tests/test_readme_banner.py::test_banner_matches_the_renderer` | pass | pass | 0.001 |
| `tests/test_readme_banner.py::test_readme_top_is_badges_then_banner_then_title` | pass | pass | 0.001 |
| `tests/test_readme_banner.py::test_hygiene_pages_are_english_and_ascii` | pass | pass | 0.001 |
| `tests/test_reconciliation_sop.py::test_sop_snippet_appends_a_verifiable_entry` | pass | pass | 0.011 |
| `tests/test_reconciliation_sop.py::test_sop_is_linked` | pass | pass | 0.001 |
| `tests/test_rtm.py::test_community_rows_name_real_tests` | pass | pass | 0.080 |
| `tests/test_rtm.py::test_verification_docs_avoid_banned_words` | pass | pass | 0.001 |
| `tests/test_sample_report.py::test_sample_report_hash_and_wording` | pass | pass | 0.001 |
| `tests/test_server_loop.py::test_serve_stdio_session_parse_and_call` | pass | pass | 0.111 |
| `tests/test_server_loop.py::test_serve_stdio_ends_a_newline_less_stream` | pass | pass | 0.109 |
| `tests/test_server_loop.py::test_serve_stdio_refuses_a_disagreeing_head` | pass | pass | 0.130 |
| `tests/test_server_loop.py::test_serve_stdio_last_resort_and_unknown_licence` | pass | pass | 0.138 |
| `tests/test_server_loop.py::test_server_main_and_upstream_builders` | pass | pass | 0.002 |
| `tests/test_server_loop.py::test_https_transport_errors` | pass | pass | 0.073 |
| `tests/test_server_loop.py::test_text_reporter_and_unsigned_signer` | pass | pass | 0.001 |
| `tests/test_server_loop.py::test_empty_log_with_a_head_fails` | pass | pass | 0.002 |
| `tests/test_server_loop.py::test_rtm_cli_and_junit_statuses` | pass | pass | 0.175 |
| `tests/test_server_loop.py::test_verification_package_loads_the_matrix` | pass | pass | 0.077 |
| `tests/test_server_loop.py::test_verification_module_entry` | pass | pass | 0.527 |
| `tests/test_stdio_e2e.py::test_allowed_denied_and_verify_cli` | pass | pass | 1.304 |
| `tests/test_stdio_e2e.py::test_approval_flow_across_two_processes` | pass | pass | 2.355 |
| `tests/test_stdio_e2e.py::test_upstream_crash_and_hang` | pass | pass | 4.954 |
| `tests/test_stdio_e2e.py::test_audit_store_failure_latches_blocked` | pass | pass | 1.183 |
| `tests/test_tamper.py::test_valid_chain` | pass | pass | 0.011 |
| `tests/test_tamper.py::test_modified_payload_is_detected` | pass | pass | 0.011 |
| `tests/test_tamper.py::test_whitespace_is_detected` | pass | pass | 0.009 |
| `tests/test_tamper.py::test_deleted_line_is_a_gap` | pass | pass | 0.007 |
| `tests/test_tamper.py::test_reordered_lines_are_detected` | pass | pass | 0.005 |
| `tests/test_tamper.py::test_unknown_hash_algo_is_rejected` | pass | pass | 0.007 |

## Dependencies

| Name | Version | SHA-256 |
|---|---|---|
| mcp | 2.3.0 | `162be8d1c7211e1da6c1fb2ffb089790725259470430197e72b28294b44e9a37` |
| rfc8785 | 0.1.4 | `2649569daf91e301d6858600a872a6e1686238c7d0dc8e7324dcd725edc9a2a1` |
| pytest | 9.1.1 | `a6879fff96cac1d940870181e27a52518cbe8e40c776f6374d382923c54d3ae0` |
| hypothesis | 6.170.1 | `46e2e4e90328839e8585145ec3a5c40d1f27444c8d8160089131fb8afc170d8d` |
| jsonschema | 4.26.0 | `a45e6d747836ee73183295a393d5461fa4acae3b6fba3c322bc252803e3f5b15` |
| PyYAML | 6.0.1 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

Report SHA-256: `d1d391948d4fa96d1bae35d6118170fa0bc365a31038856e0a241d980350a182`
