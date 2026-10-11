#!/usr/bin/env python3
"""Task4 #335: source-locked OFFLINE future CreateRef prewrite ruleset review.

No GitHub REST transport, workflow write token, Provider, or real POST is
available. Input includes a transcribed real GitHub ruleset observation;
passing only proves offline shape and refusal logic. Future authorized
writer MUST independently query live rulesets and fail closed before POST.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
from scripts import task4_330_github_create_ref_candidate_review_only_v1 as parent
from scripts import task4_333_github_readonly_prestate_review_only_v1 as base_guards

CONTRACT=ROOT/"contracts/TASK4_335_GITHUB_RULESET_WRITER_CANDIDATE_REVIEW_V1.json"
RULE="TASK4_335_EXACT_RULESET_PREWRITE_GATE_DENIES_UNREVIEWED_CHANGE_V1"
REPO="veritasfuji-japan/veritas-task4-cas-lab"
REVIEWED_MAIN="acdb15defa5781ffe64d4ae7b2629640abe4812c"
RULESET_ID=24880024
RULESET_NAME="task4-cas-proof-ref-protection"
RULESET_UPDATED_AT="2026-10-11T22:00:45.379+09:00"
REF="refs/heads/offline-test-ledger/task4-329-de45893cb289d9bca20ab879ac6d2f73"
TARGET="9edd28eee24da559fc0ad24fd97291944acc2ed4"
FUTURE_WRITER=".github/workflows/task4-330-authorized-create-ref.yml"
RULE_TYPES=("deletion","non_fast_forward","update")
ROLES=("PREFLIGHT","A","B","C")
# Hard-coded source gates. Changing these requires NEW owner approval + PR.
REAL_GITHUB_WRITE_SOURCE_GATE=False
APPROVED_WORKFLOW_HEAD_SHA=None
PROVIDER_POST_ALLOWED=False

class Denied(ValueError):
    pass

def need(value,reason):
    if not value: raise Denied(reason)

def canonical(value):
    return json.dumps(value,sort_keys=True,ensure_ascii=False,
                      separators=(",",":"),allow_nan=False).encode("utf-8")

def sha256(value):
    return hashlib.sha256(canonical(value)).hexdigest()

def expected_ruleset():
    return {
        "id":RULESET_ID,"name":RULESET_NAME,"target":"branch",
        "source_type":"Repository","enforcement":"active",
        "conditions":{"ref_name":{"exclude":[],"include":[REF]}},
        "bypass_actors":[],
        "rules":[{"type":x} for x in RULE_TYPES],
        "current_user_can_bypass":"never",
        "updated_at":RULESET_UPDATED_AT
    }

def project_ruleset(rest):
    """Extract every security-relevant field from future REST response.

    Unknown/missing fields => fail closed. This is NOT an HTTP client.
    """
    need(type(rest) is dict,"RULESET_OBJECT_REQUIRED")
    keys=("id","name","target","source_type","enforcement",
          "conditions","bypass_actors","rules",
          "current_user_can_bypass","updated_at")
    need(all(k in rest for k in keys),"RULESET_MISSING_FIELD")
    return {key:rest[key] for key in keys}

def require_frozen_ruleset(rest):
    x=project_ruleset(rest)
    want=expected_ruleset()
    for k,v in want.items():
        need(type(x[k]) is type(v) and x[k]==v,
             "RULESET_NOT_FROZEN_OR_SAFE_"+k)
    return True

def expected_plan():
    ruleset=expected_ruleset()
    return {
       "schema":"veritas.task4.github-create-ref-reviewed-plan-only.v1",
       "rule_of_one":RULE,
       "source_main_sha":REVIEWED_MAIN,
       "lab_repository":REPO,
       "visibility_at_review":"public",
       "exact_trial_ref":REF,
       "fixed_existing_target_commit":TARGET,
       "read_only_observed_ref_status":404,
       "ruleset_api_url":"https://api.github.com/repos/"+REPO+"/rulesets/24880024",
       "ruleset":ruleset,
       "future_roles":list(ROLES),
       "future_total_runs_cap":4,
       "future_create_post_cap":2,
       "future_create_post_per_writer_cap":1,
       "future_retries_cap":0,
       "role_a_b_distinct_runners_required":True,
       "planned_max_runner_minutes_per_run":8,
       "planned_runner_minutes_total":32,
       "future_writer_workflow_path":FUTURE_WRITER,
       "exact_approved_writer_head_sha":None,
       "new_owner_github_ref_write_consent":False,
       "actual_github_post_count":0,
       "actual_provider_post_count":0,
       "real_github_cas_proven":False,
       "independent_admin_irrevocability_proven":False,
       "ruleset_mutation_prohibited_without_new_review":True,
       "source_gate_enabled":False,
       "writer_workflow_installed":False,
       "provider_dispatch":"DENY",
       "predecessor_334_run_id":"38140366944",
       "predecessor_334_job_id":"114472823935",
       "predecessor_334_artifact_id":"11702966070",
       "predecessor_334_artifact_zip_sha256":"0a77ca0f7ca3d7d18db57db9b5ee1d37003e07b510b31f92f410a293452d8c38",
       "classification":"EXACT_RULESET_SNAPSHOT_VALID_FOR_REVIEW_NOT_LIVE_ATTESTATION_OR_AUTHORIZATION"
    }

def verify_contract(data):
    need(type(data) is dict and set(data)==set(expected_plan()),
         "EXACT_REVIEW_FIELDS_REQUIRED")
    for k,v in expected_plan().items():
        need(type(data[k]) is type(v) and data[k]==v,
             "UNREVIEWED_CONTRACT_DRIFT_"+k)
    require_frozen_ruleset(data["ruleset"])
    need(parent.proposed_request()=={"ref":REF,"sha":TARGET},
         "PARENT_WRITER_REQUEST_PIN_DRIFT")
    return True

def verify_no_write():
    # If the old #330 source gates or any #333 workflow guard changes,
    # this review MUST stop instead of silently accepting the modification.
    need(parent.REAL_GITHUB_WRITE_SOURCE_GATE is False
         and parent.APPROVED_WORKFLOW_HEAD_SHA is None
         and parent.LIVE_PROVIDER_DISPATCH_ALLOWED is False,
         "PARENT_REAL_WRITE_OR_PROVIDER_MUST_REMAIN_OFF")
    base_guards.verify_gates()
    need(REAL_GITHUB_WRITE_SOURCE_GATE is False
         and APPROVED_WORKFLOW_HEAD_SHA is None
         and PROVIDER_POST_ALLOWED is False,
         "THIS_SOURCE_MUST_REMAIN_WRITE_INERT")
    need(not (ROOT/FUTURE_WRITER).exists(),
         "REAL_GITHUB_WRITE_WORKFLOW_MUST_NOT_EXIST")
    return True

def preview():
    manifest=json.loads(CONTRACT.read_text(encoding="utf-8"))
    verify_contract(manifest)
    verify_no_write()
    report={
       "rule_of_one":RULE,
       "state":"REVIEW_ONLY_DENY_ALL_ACTUAL_WRITES",
       "manifest_sha256":sha256(manifest),
       "ruleset_snapshot_sha256":sha256(manifest["ruleset"]),
       "proposed_create_body_sha256":sha256(parent.proposed_request()),
       "ruleset_recorded_but_not_requeried_in_job":True,
       "future_live_ruleset_preflight_required":True,
       "future_runtime_target_and_ref_preflight_required":True,
       "future_billing_and_owner_consent_required":True,
       "four_independent_runs_observed":False,
       "github_create_post_count":0,
       "provider_post_count":0,
       "github_ref_write_authorized":False,
       "single_use_irrevocability_proven":False,
       "provider_dispatch":"DENY"
    }
    report["report_sha256"]=sha256(report)
    return report

def real_create_ref_once(*args,**kwargs):
    """Deliberately impossible regardless of tokens, environment, args."""
    raise Denied("TASK4_335_NO_REAL_GITHUB_WRITE_AUTHORIZED")

def main(argv):
    need(len(argv)==2,"EXACT_ONE_OFFLINE_REPORT_REQUIRED")
    dest=Path(argv[1]).resolve()
    need(dest.parent==(ROOT/"results").resolve()
         and dest.name=="task4-335-ruleset-prewrite-offline-review.json"
         and not dest.exists(),"ONLY_NEW_FIXED_OFFLINE_REPORT")
    report=preview()
    dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",
                    encoding="utf-8")
    print("TASK4_335_EXACT_RULESET_PREWRITE_REVIEW_ONLY_NO_REAL_CREATE_REF")

if __name__=="__main__":
    main(sys.argv)
