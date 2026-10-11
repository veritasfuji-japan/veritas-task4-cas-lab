#!/usr/bin/env python3
"""Task4 #332: pure local authorization-preflight reviewer; NO network or write functions."""
from __future__ import annotations
import ast
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts/TASK4_332_REAL_CAS_APPROVAL_PREFLIGHT_V1.json"
LAB = "veritasfuji-japan/veritas-task4-cas-lab"
BASE = "6ef46b4cf49685a2599adc98ed0498de4575e1f8"
REF = "refs/heads/offline-test-ledger/task4-329-de45893cb289d9bca20ab879ac6d2f73"
TARGET = "9edd28eee24da559fc0ad24fd97291944acc2ed4"
ARTIFACT_ZIP = "6acf07de97712a6598cee34d926da394eeadaa3b02c88f55e5ee4a4373a2c5dc"
RULE = "TASK4_332_REAL_GITHUB_CAS_APPROVAL_PREFLIGHT_DENY_UNTIL_ATTESTED_V1"

class Denied(ValueError):
    pass

def need(condition, why):
    if not condition:
        raise Denied(why)

def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")

def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()

def verify_manifest(p):
    need(type(p) is dict, "PLAN_OBJECT_REQUIRED")
    expected_keys = {
        "schema","rule_of_one","lab_repository","source_reviewed_main_sha",
        "predecessor_run_id","predecessor_job_id","predecessor_artifact_id",
        "predecessor_artifact_zip_sha256","ref","target_commit",
        "create_path","readback_path","planned_roles",
        "proposed_max_distinct_runs","proposed_max_runner_minutes_per_run",
        "proposed_total_runner_minutes","proposed_max_post_attempts",
        "proposed_max_post_attempts_per_writer","proposed_automatic_retries",
        "proposed_writer_permission","validated_private_actions_budget_minutes",
        "verified_ref_absent","verified_fixed_target_exists",
        "signed_owner_write_approval_ref","approved_frozen_writer_workflow_head_sha",
        "independent_admin_custody_attested","actual_git_ref_create_post_count",
        "actual_provider_post_count","source_gate_enabled","active_write_workflow",
        "real_cross_run_cas_proven","real_single_use_irrevocable_proven",
        "provider_dispatch","state"
    }
    need(set(p) == expected_keys, "EXACT_PLAN_FIELDS_REQUIRED")
    frozen = {
        "schema":"veritas.task4.cas-experiment-preauthorization-review-only.v1",
        "rule_of_one":RULE,"lab_repository":LAB,"source_reviewed_main_sha":BASE,
        "predecessor_run_id":"38138979918",
        "predecessor_job_id":"114468691107",
        "predecessor_artifact_id":"11701243750",
        "predecessor_artifact_zip_sha256":ARTIFACT_ZIP,"ref":REF,
        "target_commit":TARGET,
        "create_path":"/repos/"+LAB+"/git/refs",
        "readback_path":"/repos/"+LAB+"/git/ref/"+REF.removeprefix("refs/"),
        "planned_roles":["PREFLIGHT","A","B","C"],
        "proposed_max_distinct_runs":4,
        "proposed_max_runner_minutes_per_run":8,
        "proposed_total_runner_minutes":32,
        "proposed_max_post_attempts":2,
        "proposed_max_post_attempts_per_writer":1,
        "proposed_automatic_retries":0,
        "proposed_writer_permission":"contents:write (future only, not provisioned)",
        "validated_private_actions_budget_minutes":None,
        "verified_ref_absent":None,"verified_fixed_target_exists":None,
        "signed_owner_write_approval_ref":None,
        "approved_frozen_writer_workflow_head_sha":None,
        "independent_admin_custody_attested":False,
        "actual_git_ref_create_post_count":0,"actual_provider_post_count":0,
        "source_gate_enabled":False,"active_write_workflow":False,
        "real_cross_run_cas_proven":False,
        "real_single_use_irrevocable_proven":False,
        "provider_dispatch":"DENY","state":"REVIEW_ONLY_NOT_AUTHORIZED"
    }
    for key, val in frozen.items():
        need(type(p[key]) is type(val) and p[key] == val,
             "FROZEN_OR_UNAUTHORIZED_FIELD_"+key)
    return True

def literal_assignments(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    values = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if target.id in values:
                        raise Denied("DUPLICATE_SECURITY_ASSIGNMENT_"+target.id)
                    values[target.id] = node.value
    return values

def verify_source_gates():
    parent_path = ROOT / "scripts/task4_330_github_create_ref_candidate_review_only_v1.py"
    values = literal_assignments(parent_path)
    for name, desired in (("REAL_GITHUB_WRITE_SOURCE_GATE",False),
                          ("APPROVED_WORKFLOW_HEAD_SHA",None),
                          ("LIVE_PROVIDER_DISPATCH_ALLOWED",False)):
        node = values.get(name)
        need(isinstance(node, ast.Constant) and type(node.value) is type(desired)
             and node.value == desired,"PARENT_SOURCE_GATE_DRIFT_"+name)
    workflows = sorted((ROOT/".github/workflows").glob("*.yml"))

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
    for workflow in workflows:
        body=workflow.read_text(encoding="utf-8")
        need("  workflow_dispatch:" in body and
             "permissions:\\n  contents: read".replace("\\n","\n") in body and
             "persist-credentials: false" in body,
             "WORKFLOW_NOT_MANUAL_READ_ONLY_"+workflow.name)
        if workflow.name=="task4-338-live-authenticated-readonly-preflight-manual.yml":
            need(body.count(token_assignment)==1
                 and body.count("github.token")==1
                 and "      contents: read" in body
                 and "GITHUB_TOKEN:" not in body
                 and 'github.actor == \'veritasfuji-japan\'' in body
                 and 'github.run_attempt == 1' in body,
                 "TASK4_338_SCOPED_GITHUB_READ_TOKEN_REQUIRED")
            safe_body=body.replace(token_assignment,"TASK4_338_EPHEMERAL_READ_ONLY_TOKEN_PLACEHOLDER")
        else:
            need(token_assignment not in body and "github.token" not in body,
                 "NO_TOKEN_ACCESS_IN_EXISTING_OFFLINE_WORKFLOWS")
            safe_body=body
        for forbidden in ("contents: write","pull_request:","pull_request_target:",
                          "push:","secrets.","github.token","gh api --method POST"):
            need(forbidden not in safe_body, "UNEXPECTED_PRIVILEGED_WORKFLOW_"+workflow.name)
    need(not list((ROOT/".github/workflows").glob("*.yaml")),
         "UNREVIEWED_YAML_WORKFLOW")
    return [w.name for w in workflows]

def review():
    manifest = json.loads(CONTRACT.read_text(encoding="utf-8"))
    verify_manifest(manifest)
    workflows = verify_source_gates()
    report = {
        "rule_of_one":RULE,"classification":"OFFLINE_REVIEW_VALID_BUT_NOT_AUTHORIZED",
        "source_reviewed_main_sha":BASE,"manifest_sha256":digest(manifest),
        "workflow_names":workflows,
        "future_four_real_runs_proven":False,
        "actual_git_ref_create_post_count":0,"actual_provider_post_count":0,
        "private_actions_budget_verified":False,
        "owner_write_approval_present":False,
        "immutable_nonresettable_single_use_proven":False,
        "real_github_write_authorized":False,"provider_dispatch":"DENY"
    }
    report["report_sha256"] = digest(report)
    return report

def main(argv):
    need(len(argv)==2,"EXACT_OUTPUT_ARG_REQUIRED")
    path=Path(argv[1]).resolve()
    need(path.parent == (ROOT/"results").resolve() and
         path.name == "task4-332-preauthorization-offline-review.json" and
         not path.exists(),"NEW_FIXED_LOCAL_REPORT_ONLY")
    report=review()
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print("TASK4_332_REVIEW_ONLY_WRITE_NOT_AUTHORIZED_PROVIDER_DENY")

if __name__ == "__main__":
    main(sys.argv)
