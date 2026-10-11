#!/usr/bin/env python3
"""Task4 #333: frozen read-only GitHub API observation, never a live permission grant."""
from __future__ import annotations
import ast
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
CONTRACT=ROOT/"contracts/TASK4_333_GITHUB_READONLY_OBSERVATION_V1.json"
REPO="veritasfuji-japan/veritas-task4-cas-lab"
MAIN="ee69b8a5e936354b9cf1f24e311b08ce593fde92"
TARGET="9edd28eee24da559fc0ad24fd97291944acc2ed4"
REF="refs/heads/offline-test-ledger/task4-329-de45893cb289d9bca20ab879ac6d2f73"
PREV_ZIP="d084399be98e8591cbaabc93b17e75986cf838a4ec263dd03d7beaa5fc00370c"
RULE="TASK4_333_ACTUAL_GITHUB_READ_ONLY_PRESTATE_NOT_AUTHORIZATION"

class Denied(ValueError):
    pass

def need(ok,reason):
    if not ok: raise Denied(reason)

def digest(x):
    return hashlib.sha256(json.dumps(x,sort_keys=True,ensure_ascii=False,
           separators=(",",":"),allow_nan=False).encode()).hexdigest()

def expected():
    return {
        "schema":"veritas.task4.github-readonly-observation-freeze.v1",
        "rule_of_one":RULE,"observation_date_utc":"2026-10-11",
        "observation_method":"connected GitHub REST GET, read-only; evidence transcribed into repository, not a signed API attestation",
        "lab_repository":REPO,"lab_visibility":"private",
        "lab_default_branch":"main","source_main_commit_sha":MAIN,
        "candidate_ref":REF,"target_existing_git_commit_sha":TARGET,
        "target_commit_get_result":"SUCCESS_SHA_MATCH",
        "candidate_ref_get_http_status":404,
        "candidate_ref_get_message":"Not Found",
        "candidate_namespace_matching_ref_count":0,
        "repository_get_result":"SUCCESS_PRIVATE_REPO",
        "github_rulesets_get_http_status":403,
        "github_rulesets_error_message":"Upgrade to GitHub Pro or make this repository public to enable this feature.",
        "github_branch_protection_get_http_status":403,
        "github_branch_protection_error_message":"Resource not accessible by integration",
        "github_ruleset_enforcement_proven":False,
        "branch_protection_enforcement_proven":False,
        "admin_ref_immutability_proven":False,
        "private_actions_remaining_minutes":None,
        "private_actions_spending_cap_verified":False,
        "predecessor_332_run_id":"38139656085",
        "predecessor_332_job_id":"114470698728",
        "predecessor_332_artifact_id":"11702366273",
        "predecessor_332_zip_sha256":PREV_ZIP,
        "predecessor_332_test_results":"35 passed",
        "actual_write_attempt_count_in_333":0,
        "actual_provider_post_count_in_333":0,
        "future_writer_workflow_authorized":False,
        "fresh_owner_ref_write_consent_present":False,
        "real_cross_run_cas_proven":False,
        "nonresettable_consume_once_authority_proven":False,
        "classification":"READ_ONLY_SNAPSHOT_ONLY_NOT_RUNTIME_AUTHORIZATION",
        "provider_dispatch":"DENY"
    }

def verify(data):
    need(type(data) is dict and set(data)==set(expected()),"EXACT_OBSERVATION_SCHEMA_ONLY")
    for k,v in expected().items():
        need(type(data[k]) is type(v) and data[k]==v,"OBSERVATION_OR_AUTHORITY_DRIFT_"+k)
    return True

def verify_gates():
    file=ROOT/"scripts/task4_330_github_create_ref_candidate_review_only_v1.py"
    tree=ast.parse(file.read_text(encoding="utf-8"))
    seen={}
    for node in tree.body:
        if isinstance(node,ast.Assign):
            for item in node.targets:
                if isinstance(item,ast.Name) and item.id in {
                     "REAL_GITHUB_WRITE_SOURCE_GATE",
                     "APPROVED_WORKFLOW_HEAD_SHA",
                     "LIVE_PROVIDER_DISPATCH_ALLOWED"}:
                    need(item.id not in seen,"DUPLICATE_SOURCE_GATE_"+item.id)
                    seen[item.id]=node.value
    for k,v in (("REAL_GITHUB_WRITE_SOURCE_GATE",False),
                ("APPROVED_WORKFLOW_HEAD_SHA",None),
                ("LIVE_PROVIDER_DISPATCH_ALLOWED",False)):
        node=seen.get(k)
        need(isinstance(node,ast.Constant) and type(node.value) is type(v)
             and node.value==v,"SOURCE_GATE_NOT_CLOSED_"+k)
    workflows=list((ROOT/".github/workflows").glob("*.yml"))

    # Task4 #338 is the ONLY newly added workflow: exclusively manual,
    # globally contents:read, and ONE ephemeral github.token expression.
    expected_workflows = {
        "task4-329-readonly-manual-preflight.yml",
        "task4-330-review-only-manual.yml",
        "task4-331-offline-evidence-review-manual.yml",
        "task4-332-manual-preauthorization-review-only.yml",
        "task4-338-live-authenticated-readonly-preflight-manual.yml"
    }
    workflow_names = {p.name for p in workflows}
    need(workflow_names == expected_workflows, "UNEXPECTED_WORKFLOW_NAME_OR_COUNT")
    token_assignment = "GH_TOKEN: ${{ github.token }}"
    need(not list((ROOT/".github/workflows").glob("*.yaml")),
         "NO_UNREVIEWED_YAML_WORKFLOWS")
    for workflow in workflows:
        raw=workflow.read_text(encoding="utf-8")
        need("\n  workflow_dispatch:" in raw and
             "\npermissions:\n  contents: read" in raw and
             "persist-credentials: false" in raw,
             "NO_UNREVIEWED_WORKFLOW_PERMISSION_"+workflow.name)
        if workflow.name=="task4-338-live-authenticated-readonly-preflight-manual.yml":
            need(raw.count(token_assignment)==1
                 and raw.count("github.token")==1
                 and "      contents: read" in raw
                 and "GITHUB_TOKEN:" not in raw
                 and 'github.actor == \'veritasfuji-japan\'' in raw
                 and 'github.run_attempt == 1' in raw,
                 "TASK4_338_SCOPED_GITHUB_READ_TOKEN_REQUIRED")
            safe_raw=raw.replace(token_assignment,"TASK4_338_READ_ONLY_TOKEN_PLACEHOLDER")
        else:
            need(token_assignment not in raw and "github.token" not in raw,
                 "NO_GITHUB_CONTEXT_TOKEN_IN_OFFLINE_WORKFLOWS")
            safe_raw=raw
        for forbidden in ("contents: write","pull_request:","pull_request_target:",
                          "push:","secrets.","github.token","gh api --method POST"):
            need(forbidden not in safe_raw,"FORBIDDEN_WORKFLOW_PRIMITIVE_"+workflow.name)
    return True

def review():
    data=json.loads(CONTRACT.read_text(encoding="utf-8"))
    verify(data)
    verify_gates()
    result={
        "rule_of_one":RULE,
        "observation_sha256":digest(data),
        "classification":"OBSERVATION_FREEZE_VALID_NOT_INDEPENDENTLY_SIGNED",
        "point_in_time_ref_not_found":True,
        "target_commit_was_observed":True,
        "preflight_must_be_repeated_at_runtime":True,
        "private_actions_budget_verified":False,
        "github_ref_immutability_attested":False,
        "real_cas_proven":False,
        "git_ref_write_authorized":False,
        "provider_dispatch":"DENY",
        "real_github_post_count":0,
        "real_provider_post_count":0
    }
    result["report_sha256"]=digest(result)
    return result

def main(argv):
    need(len(argv)==2,"EXACT_REPORT_PATH_REQUIRED")
    dest=Path(argv[1]).resolve()
    need(dest.parent==(ROOT/"results").resolve()
         and dest.name=="task4-333-readonly-observation-review.json"
         and not dest.exists(),"ONLY_NEW_FIXED_OFFLINE_REPORT")
    r=review()
    dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(r,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print("TASK4_333_READ_ONLY_OBSERVATION_NOT_RUNTIME_PERMISSION")

if __name__=="__main__":
    main(sys.argv)
