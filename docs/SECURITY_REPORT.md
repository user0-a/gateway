# WWGateWay — security report

Generated 2026-10-09 14:21 UTC by `tools/security_report.py` from real runs.

## 1. Automated security tests

Result: `======================== 39 passed, 1 warning in 4.00s =========================`

| Suite | Test | Result |
|---|---|---|
| test_gateway | `test_low_risk_unrestricted_action_is_allowed_directly` | PASSED |
| test_gateway | `test_role_restricted_action_requires_employee_approved_plan` | PASSED |
| test_gateway | `test_agent_cannot_self_assert_a_subject_or_role` | PASSED |
| test_gateway | `test_block_rule_denies_matching_action` | PASSED |
| test_gateway | `test_batch_reports_each_decision` | PASSED |
| test_gateway | `test_system_risk_tolerance_is_stricter_than_global` | PASSED |
| test_gateway | `test_plan_is_not_usable_before_employee_approval` | PASSED |
| test_gateway | `test_plan_requires_known_employee_owner` | PASSED |
| test_gateway | `test_only_the_owner_can_approve_and_only_the_exact_hash` | PASSED |
| test_gateway | `test_step_token_is_bound_to_plan_and_outside_actions_need_extension` | PASSED |
| test_gateway | `test_plan_extension_needs_owner_signature` | PASSED |
| test_gateway | `test_cancelled_plan_issues_no_more_tokens` | PASSED |
| test_gateway | `test_step_issuance_is_limited` | PASSED |
| test_gateway | `test_admin_ui_has_no_prefilled_secret` | PASSED |
| test_security | `test_signed_agent_requests_reject_missing_wrong_replayed_stale_and_tampered` | PASSED |
| test_security | `test_agent_with_registered_key_cannot_fall_back_to_api_key` | PASSED |
| test_security | `test_legacy_agent_works_only_for_unrestricted_actions_and_gets_unbound_tokens` | PASSED |
| test_security | `test_tokens_are_eddsa_jws_and_jwks_is_published` | PASSED |
| test_security | `test_key_rotation_keeps_old_tokens_valid_until_retired` | PASSED |
| test_security | `test_audit_chain_detects_modification_and_deletion` | PASSED |
| test_security | `test_audit_export_is_json_lines` | PASSED |
| test_security | `test_admin_endpoints_and_introspection_require_admin_key` | PASSED |
| test_security | `test_agent_rate_limit` | PASSED |
| test_security | `test_production_refuses_dev_configuration` | PASSED |
| test_security | `test_canonicalization_is_identical_in_gateway_and_sdk` | PASSED |
| test_verifier | `test_happy_path_and_single_use` | PASSED |
| test_verifier | `test_same_plan_step_cannot_execute_twice_even_with_a_new_token` | PASSED |
| test_verifier | `test_binding_checks` | PASSED |
| test_verifier | `test_proof_of_possession` | PASSED |
| test_verifier | `test_proof_replay` | PASSED |
| test_verifier | `test_time_checks` | PASSED |
| test_verifier | `test_forged_and_confused_tokens` | PASSED |
| test_verifier | `test_data_token_cannot_be_used_as_action_token` | PASSED |
| test_verifier | `test_unbound_legacy_tokens_are_rejected_when_pop_is_required` | PASSED |
| test_verifier | `test_revocation_risk_suspension_and_plan_cancellation_reach_the_bank` | PASSED |
| test_verifier | `test_fail_closed_when_policy_cannot_be_refreshed` | PASSED |
| test_verifier | `test_wrong_issuer_is_rejected` | PASSED |
| test_verifier | `test_replayed_old_policy_snapshot_is_rejected` | PASSED |
| test_verifier | `test_policy_snapshot_is_signed` | PASSED |

## 2. Mutation check (do the tests have teeth?)

Each protection is disabled in turn; the suite must fail. `SURVIVED` would mean a protection without a test.

```
verifier: signature check                 caught   test_forged_and_confused_tokens
verifier: alg must be EdDSA               caught   test_forged_and_confused_tokens
verifier: token type                      caught   test_data_token_cannot_be_used_as_action_token
verifier: issuer                          caught   test_wrong_issuer_is_rejected
verifier: audience                        caught   test_binding_checks
verifier: expiry                          caught   test_time_checks
verifier: not-before                      caught   test_time_checks
verifier: action binding                  caught   test_binding_checks
verifier: params binding                  caught   test_binding_checks
verifier: token single use                caught   test_happy_path_and_single_use
verifier: plan step executes once         caught   test_same_plan_step_cannot_execute_twice_even_with_a_new_token
verifier: revoked jti                     caught   test_revocation_risk_suspension_and_plan_cancellation_reach_the_bank
verifier: suspended agent                 caught   test_revocation_risk_suspension_and_plan_cancellation_reach_the_bank
verifier: cancelled plan                  caught   test_revocation_risk_suspension_and_plan_cancellation_reach_the_bank
verifier: live risk tolerance             caught   test_revocation_risk_suspension_and_plan_cancellation_reach_the_bank
verifier: PoP required                    caught   test_unbound_legacy_tokens_are_rejected_when_pop_is_required
verifier: proof present                   caught   test_proof_of_possession
verifier: proof key thumbprint            caught   test_proof_of_possession
verifier: proof method                    caught   test_proof_of_possession
verifier: proof url                       caught   test_proof_of_possession
verifier: proof bound to token            caught   test_proof_of_possession
verifier: proof freshness                 caught   test_proof_of_possession
verifier: proof single use                caught   test_proof_replay
verifier: policy snapshot signature       caught   test_policy_snapshot_is_signed
verifier: fail closed on stale policy     caught   test_fail_closed_when_policy_cannot_be_refreshed
verifier: fetched snapshot freshness      caught   test_replayed_old_policy_snapshot_is_rejected
verifier: data table scope                caught   test_data_token_cannot_be_used_as_action_token
verifier: row filters                     caught   test_data_token_cannot_be_used_as_action_token
gateway: request signature                caught   test_signed_agent_requests_reject_missing_wrong_replayed_stale_and_tampered
gateway: request nonce replay             caught   test_signed_agent_requests_reject_missing_wrong_replayed_stale_and_tampered
gateway: request timestamp window         caught   test_signed_agent_requests_reject_missing_wrong_replayed_stale_and_tampered
gateway: keyed agent cannot use API key   caught   test_low_risk_unrestricted_action_is_allowed_directly
gateway: legacy API key comparison        caught   test_legacy_agent_works_only_for_unrestricted_actions_and_gets_unbound_tokens
gateway: only plan owner approves         caught   test_only_the_owner_can_approve_and_only_the_exact_hash
gateway: exact plan hash approval         caught   test_only_the_owner_can_approve_and_only_the_exact_hash
gateway: role claim mismatch              caught   test_agent_cannot_self_assert_a_subject_or_role
gateway: role from directory              caught   test_agent_cannot_self_assert_a_subject_or_role
gateway: subject must be verified         caught   test_agent_cannot_self_assert_a_subject_or_role
gateway: employee-approved plan required  caught   test_role_restricted_action_requires_employee_approved_plan
gateway: plan must be approved            caught   test_plan_is_not_usable_before_employee_approval
gateway: plan cancellation                caught   test_cancelled_plan_issues_no_more_tokens
gateway: outside plan                     caught   test_step_token_is_bound_to_plan_and_outside_actions_need_extension
gateway: plan step parameters             caught   test_step_token_is_bound_to_plan_and_outside_actions_need_extension
gateway: plan belongs to agent            caught   test_step_token_is_bound_to_plan_and_outside_actions_need_extension
gateway: step issuance limit              caught   test_step_issuance_is_limited
gateway: block rules                      caught   test_block_rule_denies_matching_action
gateway: risk tolerance                   caught   test_batch_reports_each_decision
gateway: extension owner check            caught   test_plan_extension_needs_owner_signature
gateway: admin authentication             caught   test_admin_endpoints_and_introspection_require_admin_key
gateway: production config check          caught   test_production_refuses_dev_configuration
gateway: rate limit                       caught   test_agent_rate_limit
gateway: audit chain verification         caught   test_audit_chain_detects_modification_and_deletion
gateway: API keys stored hashed           caught   test_legacy_agent_works_only_for_unrestricted_actions_and_gets_unbound_tokens

53/53 protections caught by tests
```

## 3. Latency

```
gateway issuance (HTTP, signed agent request, policy, audit)
  n=300  p50=9.67 ms  p95=16.61 ms  p99=19.48 ms
bank-side local verification (signature, PoP, single use, policy)
  n=300  p50=0.39 ms  p95=0.68 ms  p99=0.82 ms
```

Issuance includes the HTTP stack, signed-request verification, policy evaluation and the audit write.
Bank-side verification is local (no network call per request).

## 4. Java verifier conformance

```
vectors passed: 38, failed: 0
```

The Java verifier is checked against vectors generated by the Python reference (`tools/make_java_vectors.py`).
