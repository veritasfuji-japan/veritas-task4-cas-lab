#!/usr/bin/env python3
"""Task4 #329 isolated-lab READ-ONLY preflight, with ZERO GitHub ref writes.

This module is a pure offline plan/fixture validator. It never contacts
api.github.com, never obtains a token, and never claims a GitHub CAS proof.
Even two perfectly shaped synthetic 201/422 observations cannot be promoted
to real cross-Action-runs evidence or live Provider permission.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re

RULE = "TASK4_329_ISOLATED_LAB_READONLY_PREFLIGHT_V1"
LAB = "veritasfuji-japan/veritas-task4-cas-lab"
SOURCE = "veritasfuji-japan/rcc-revas-veritas-benchmark"
LAB_INITIAL_MAIN = "058cae0a86fdceafdab8408c225f6059c40feb2b"
SOURCE_MERGED_MAIN = "e3365d35054c06df09a37f3f4926bbe6c2fdba06"
CASE = "banking:user_task_4:injection_task_0:direct"
PRESTATE = "8b653f253d3b2b033ad2baebc938bb66cb09719be8b488a470e7e82d25abbe14"
ATTACK = "0d5011fb8b275e313c83da127698f19a77095d44e82a81b4d5804046c3cb61a9"
TRIAL_ID = "task4-329-github-ref-cas-isolated-lab-v1"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
ROOT = Path(__file__).resolve().parents[1]

class Denied(ValueError):
    pass

def require(ok, reason):
    if not ok:
        raise Denied(reason)

def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")

def sha256(value):
    return hashlib.sha256(canonical(value)).hexdigest()

def frozen_scope():
    return {
        "source_repo": SOURCE, "source_main_sha": SOURCE_MERGED_MAIN,
        "lab_repo": LAB, "lab_initial_main_sha": LAB_INITIAL_MAIN,
        "case": CASE, "native_prestate_sha256": PRESTATE,
        "native_attack_sha256": ATTACK, "trial_id": TRIAL_ID
    }

SCOPE_SHA256 = "de45893cb289d9bca20ab879ac6d2f73a09d8f36dfc9646895b6076f41209728"
REF = "refs/heads/offline-test-ledger/task4-329-" + SCOPE_SHA256[:32]
GET_PATH = "/repos/" + LAB + "/git/ref/" + REF.removeprefix("refs/")
FUTURE_POST_PATH = "/repos/" + LAB + "/git/refs"

def check_static_identity():
    require(sha256(frozen_scope()) == SCOPE_SHA256,
            "PINNED_LAB_OR_NATIVE_SCOPE_HASH_MISMATCH")
    require(REF.startswith("refs/heads/offline-test-ledger/task4-329-") and
            REF.endswith(SCOPE_SHA256[:32]) and
            GET_PATH.startswith("/repos/" + LAB + "/git/ref/heads/"),
            "FIXED_TEST_REF_NAMESPACE_REQUIRED")
    return True

def read_only_plan(*, branch="refs/heads/main", head_sha=LAB_INITIAL_MAIN):
    check_static_identity()
    require(branch == "refs/heads/main" and type(head_sha) is str
            and HEX40.fullmatch(head_sha) is not None,
            "MUST_BE_CHECKED_OUT_ON_LAB_MAIN_OR_VALID_COMMIT")
    p = {
        "rule_of_one": RULE,
        "scope_sha256": SCOPE_SHA256,
        "lab_repository": LAB,
        "lab_visibility": "PRIVATE_OWNER_VERIFIED_AT_PLANNING_TIME",
        "lab_bootstrap_main_sha": LAB_INITIAL_MAIN,
        "checked_out_main_sha": head_sha,
        "source_merged_main_sha": SOURCE_MERGED_MAIN,
        "research_case": CASE,
        "test_ref_proposal_only": REF,
        "read_only_future_get_path": GET_PATH,
        "future_write_path_not_called": FUTURE_POST_PATH,
        "scope": "READ_ONLY_PREPARATION_NO_GITHUB_WRITE_ACTIONS",
        "actual_independent_actions_run_ids": [],
        "actual_remote_cas_create_successes": 0,
        "actual_remote_cas_duplicate_refusals": 0,
        "actual_github_ref_writes": 0,
        "actual_github_api_calls": 0,
        "real_provider_posts": 0,
        "real_bank_effects": 0,
        "new_real_model_utility_scores": 0,
        "manual_only_workflow_trigger": True,
        "workflow_token_permissions": "contents:read",
        "real_git_ref_cas_proven": False,
        "immutable_ref_or_admin_separation_proven": False,
        "separate_github_runners_observed": False,
        "billing_free_private_actions_minutes_verified": False,
        "new_live_provider_approval": False,
        "ref_creation_or_credential_use_approval": False,
        "real_provider_dispatch": "DENY",
        "classification": "OFFLINE_READONLY_LAB_BOOTSTRAP_NOT_LIVE_GITHUB_CAS"
    }
    p["report_sha256"] = sha256(p)
    return p

def check_synthetic_events(events):
    """Shape-check fake receipts WITHOUT upgrading them to actual GitHub evidence.

    Never trust an HTTP 422 alone as a collision. All observations here are
    literal SYNTHETIC_TEST_ONLY values. The real cross-run auditor is absent.
    """
    check_static_identity()
    require(type(events) is list and len(events) == 3, "THREE_FAKE_EVENTS_REQUIRED")
    expected = (("A", 201, "created"), ("B", 422, "reference_already_exists"),
                ("C", 422, "reference_already_exists"))
    for event, (label, status, outcome) in zip(events, expected):
        require(type(event) is dict and set(event) == {
            "fake_run_id", "http_status", "outcome", "ref", "source",
            "provider_post_allowed", "real_github_api_contacted"
        }, "FAKE_OBSERVATION_FIELD_DRIFT")
        require(event["source"] == "SYNTHETIC_TEST_ONLY" and
                event["fake_run_id"] == label and
                type(event["http_status"]) is int and
                event["http_status"] == status and
                event["outcome"] == outcome and
                event["ref"] == REF and
                event["provider_post_allowed"] is False and
                event["real_github_api_contacted"] is False,
                "FAKE_HTTP_OUTCOME_NOT_EXACTLY_PINNED")
    return {
       "synthetic_fixture_shape_valid": True,
       "real_github_ref_cas_proven": False,
       "real_github_api_contacted": False,
       "real_provider_post_allowed": False
    }

def synthetic_events():
    return [
       {"fake_run_id": who, "http_status": code, "outcome": outcome,
        "ref": REF, "source": "SYNTHETIC_TEST_ONLY",
        "provider_post_allowed": False, "real_github_api_contacted": False}
       for who, code, outcome in (
           ("A", 201, "created"),
           ("B", 422, "reference_already_exists"),
           ("C", 422, "reference_already_exists")
       )
    ]

def write_report(path, *, branch, head_sha):
    dest = Path(path).resolve()
    require(dest.parent == (ROOT / "results").resolve() and
            dest.name == "task4-329-readonly-plan.json" and not dest.exists(),
            "ONLY_NEW_LOCAL_PINNED_EVIDENCE_REPORT")
    report = read_only_plan(branch=branch, head_sha=head_sha)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
    return report

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--ref", default="refs/heads/main")
    parser.add_argument("--head-sha", required=True)
    args = parser.parse_args()
    report = write_report(args.output, branch=args.ref, head_sha=args.head_sha)
    require(report["actual_github_ref_writes"] == 0 and
            report["real_provider_dispatch"] == "DENY",
            "WRITES_OR_LIVE_SEND_MUST_NEVER_BE_PERMITTED")
    print("TASK4_329_READONLY_LAB_PREFLIGHT_ONLY_REAL_GITHUB_CAS_UNPROVEN")

if __name__ == "__main__":
    main()
