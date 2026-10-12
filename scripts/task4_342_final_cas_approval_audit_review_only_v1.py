#!/usr/bin/env python3
"""Task4 #342: strict, OFFLINE-ONLY final CAS consent / audit plan review.

This module cannot authorize or execute GitHub writes. Its output is DENY even
when a proposed approval input is forged. Exact owner consent to an exact
future writer workflow SHA must be obtained in a separate decision.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from scripts import task4_330_github_create_ref_candidate_review_only_v1 as source
from scripts import task4_332_cas_pre_dispatch_authorization_review_only_v1 as guard
from scripts import task4_335_ruleset_prewrite_candidate_review_only_v1 as prewrite
from scripts import task4_336_future_workflow_staged_review_only_v1 as staged
from scripts import task4_341_separate_read_bypass_evidence_review_only_v1 as witness

CONTRACT=ROOT/"contracts/TASK4_342_REAL_CAS_FINAL_APPROVAL_AUDIT_REVIEW_ONLY_V1.json"
RULE="TASK4_342_REAL_CAS_FINAL_APPROVAL_AND_INDEPENDENT_AUDIT_PLAN_NOT_AUTHORIZATION"
SCHEMA="veritas.task4.real-github-cross-run-cas-final-approval-and-audit-review-only.v1"
REPO="veritasfuji-japan/veritas-task4-cas-lab"
REPO_ID=1414228001
REVIEWED_MAIN="f48021f737a66f119569ac586f8d6ad4b1de34d9"
TARGET="9edd28eee24da559fc0ad24fd97291944acc2ed4"
REF="refs/heads/offline-test-ledger/task4-329-de45893cb289d9bca20ab879ac6d2f73"
RULESET_ID=24880024
UPDATED_AT="2026-10-11T22:00:45.379+09:00"
WRITER=".github/workflows/task4-330-authorized-create-ref.yml"
CLASSIFICATION="OFFLINE_FINAL_APPROVAL_AUDIT_PLAN_ONLY_NO_GITHUB_WRITE_AUTHORITY"
ROLES=("PREFLIGHT","A","B","C")
HEX40=re.compile(r"[0-9a-f]{40}\\Z")

PREDECESSOR={
    "task4_340_run_id":38186765875,
    "task4_340_job_id":114610648509,
    "task4_340_artifact_id":11719338461,
    "task4_340_artifact_zip_sha256":"51e4af5d773b2c158cc128b45b1bb2501980d84c6e10b37aae4526be0c550a34",
    "task4_340_source_head_sha":"cd1d137da8af98620ddd59f9adc1bee889128955",
    "task4_341_run_id":38187628606,
    "task4_341_job_id":114613290354,
    "task4_341_artifact_id":11719839558,
    "task4_341_artifact_zip_sha256":"26746b9f9c4271a56210749306d12619e1ce46588318060591ecfc3f58e5d0ae",
    "task4_341_source_head_sha":REVIEWED_MAIN,
    "task4_341_junit_passed":261,
    "bypass_at_340_run_proven":False,
    "independent_runtime_bypass_signed_attestation_present":False
}
TRIAL={
    "ref":REF,
    "existing_target_commit_sha":TARGET,
    "protected_ruleset_id":RULESET_ID,
    "ruleset_updated_at":UPDATED_AT,
    "required_rules":["deletion","non_fast_forward","update"],
    "required_bypass_actors":[],
    "required_current_user_can_bypass":"never",
    "ruleset_not_admin_irrevocable":True,
    "candidate_ref_404_at_separate_review":True,
    "candidate_ref_absent_at_future_dispatch_unproven":True
}
CONSENT={
    "approved":False,"approval_record_id":None,
    "approval_record_sha256":None,
    "approved_exact_writer_workflow_head_sha":None,
    "approved_actor":None,"approved_repo_ref_target_tuple":None,
    "approval_expires_at":None,"approved_github_write_token_scope":None,
    "approved_billing_max_usd":None,
    "previous_api_or_pr_approval_reused":False,
    "merge_or_ci_success_never_authorization":True
}
PLAN={
    "roles":list(ROLES),"max_total_workflow_runs":4,
    "max_total_create_ref_posts":2,
    "max_posts_per_writer_role":1,"max_retries":0,
    "max_manual_replays":0,"max_minutes_per_run":8,
    "max_aggregate_runner_minutes":32,
    "concurrent_writers_require_distinct_runs":True,
    "concurrent_writers_require_distinct_jobs":True,
    "concurrent_writers_require_separate_ephemeral_credentials":True,
    "cross_run_temporal_overlap_must_be_observed":True,
    "estimated_runtime_cost_not_authorized":True,
    "writer_roles":["A","B"],"nonwriting_roles":["PREFLIGHT","C"]
}
GATES=[
    "SEPARATE_EXPLICIT_OWNER_APPROVAL_WITH_EXACT_WORKFLOW_HEAD_SHA_AND_REPO_REF_TARGET",
    "APPROVED_PERMISSIONS_AND_COST_CEILING_EXPLICIT_WITH_EXPIRY",
    "RECHECK_MAIN_AND_RUN_WORKFLOW_HEAD_AND_SINGLE_ATTEMPT",
    "INDEPENDENT_RULESET_SCOPE_AND_BYPASS_AT_RUNTIME",
    "RECHECK_REF_NONEXISTENCE_BEFORE_EACH_WRITE_WITH_NO_ASSUMPTIONS",
    "FRESH_APPROVAL_BOUND_TO_OBSERVED_RULESET_AND_REF_SNAPSHOT",
    "SEPARATE_EPHEMERAL_WRITER_RUN_CREDENTIALS_AND_FINITE_ATTEMPTS",
    "NO_PROVIDER_SECRETS_OR_EXTERNAL_EFFECTS",
    "STOP_IF_ADMIN_RULESET_MUTATION_OR_BYPASS_VISIBILITY_GAP",
    "AUTHORITY_AT_EXECUTION_NOT_INFERRED_FROM_ISSUANCE"
]
AUDIT=[
    "REAL_RUN_JOB_IDS_HEAD_SHAS_AND_WORKFLOW_BLOB_SHAS",
    "PER_RUN_JOB_STARTED_AND_COMPLETED_TIMESTAMPS",
    "PER_WRITER_PRE_GET_HTTP_STATUSES_AND_BODY_SHA256",
    "PER_WRITER_SINGLE_POST_EXACT_REF_AND_TARGET_REQUEST_BODY_SHA256",
    "PER_WRITER_SERVER_HTTP_STATUS_RESPONSE_DIGEST_AND_ACCEPTED_REF_SHA",
    "SERVER_SIDE_REF_STATE_READ_BY_DISTINCT_AUDIT_CREDENTIAL",
    "SIGNED_INDEPENDENT_RULESET_BYPASS_SNAPSHOT_AT_EXECUTION_OR_MARK_UNPROVEN",
    "POST_START_END_WINDOWS_WITH_CROSS_RUN_OVERLAP_INDEPENDENTLY_CORROBORATED",
    "TOTAL_REAL_POSTS_TOKENS_RUN_ATTEMPTS_AND_RETRIES_ACCOUNTED",
    "FAILED_OR_AMBIGUOUS_REQUESTS_TRIGGER_STOP_WITHOUT_AUTOMATIC_RETRY",
    "ALL_EVIDENCE_ARTIFACT_DIGESTS_AND_PINNED_CODE_ORIGIN",
    "ADMIN_RESET_OR_RULESET_MUTABILITY_LIMITATION_DISCLOSED"
]
PROMOTION_DENY=[
    "HTTP_404_ONLY_NEVER_CAS",
    "OFFLINE_SIMULATION_NEVER_REAL_CAS",
    "ONE_201_ONE_422_WITHOUT_OVERLAP_NEVER_RACE_PROOF",
    "SEPARATE_BYPASS_SNAPSHOT_NEVER_SAME_RUN_ATTESTATION",
    "READ_ONLY_GREEN_NEVER_WRITE_APPROVAL",
    "GITHUB_PROTECTED_REF_NEVER_ADMIN_IRREVOCABILITY",
    "MERGE_IS_NEVER_EXPLICIT_DISPATCH_APPROVAL"
]
STATE={
    "writer_workflow_installed":False,
    "github_write_source_gate_enabled":False,
    "approved_workflow_head_sha":None,
    "privileged_token_granted":False,
    "owner_approval_present":False,
    "independent_signed_auditor_present":False,
    "actual_github_create_ref_post_count":0,
    "actual_provider_post_count":0,
    "real_cross_run_cas_proven":False,
    "admin_irrevocable_one_time_consumption_proven":False,
    "provider_dispatch":"DENY",
    "final_classification":CLASSIFICATION
}

class Denied(ValueError):pass

def need(ok,reason):
    if not ok:raise Denied(reason)

def canonical(v):
    return json.dumps(v,sort_keys=True,ensure_ascii=False,
                      separators=(",",":"),allow_nan=False).encode("utf-8")

def digest(v):
    return hashlib.sha256(canonical(v)).hexdigest()

def exact(data,expected,reason):
    need(type(data) is type(expected),reason+"_TYPE")
    if isinstance(expected,dict):
        need(set(data)==set(expected),reason+"_FIELDS")
        for key,want in expected.items():
            exact(data[key],want,reason+"_"+key)
    elif isinstance(expected,list):
        need(len(data)==len(expected),reason+"_LENGTH")
        for i,(actual,want) in enumerate(zip(data,expected)):
            exact(actual,want,reason+"_"+str(i))
    else:
        need(data==expected,reason+"_CHANGED")

def expected_contract():
    return {
        "schema":SCHEMA,"rule_of_one":RULE,
        "repository":REPO,"repository_id":REPO_ID,"visibility":"public",
        "source_main_at_review":REVIEWED_MAIN,
        "predecessor_evidence":PREDECESSOR,
        "trial":TRIAL,"planned_writer_workflow":WRITER,
        "explicit_separate_owner_consent":CONSENT,
        "four_role_experiment_plan":PLAN,
        "dispatch_gates_required":GATES,
        "required_independent_audit_evidence":AUDIT,
        "forbidden_proof_promotions":PROMOTION_DENY,
        "current_state":STATE
    }

def verify_no_write_source():
    # The CURRENT shipped source MUST remain incapable of an actual GitHub write.
    need(source.REAL_GITHUB_WRITE_SOURCE_GATE is False
         and source.APPROVED_WORKFLOW_HEAD_SHA is None
         and source.LIVE_PROVIDER_DISPATCH_ALLOWED is False,
         "REAL_WRITER_OR_PROVIDER_GATE_OPEN")
    guard.verify_source_gates()
    prewrite.verify_no_write()
    need(not (ROOT/WRITER).exists(),"REAL_CREATE_REF_WORKFLOW_INSTALLED")
    need((ROOT/"docs/templates/task4-336-four-role-create-ref-STAGED-NOT-INSTALLED.yml").exists(),
         "INERT_TEMPLATE_MISSING")
    need(HEX40.fullmatch(REVIEWED_MAIN) is not None
         and HEX40.fullmatch(TARGET) is not None,
         "SOURCE_SHA_FORMAT_INVALID")
    return True

def verify(data):
    exact(data,expected_contract(),"FINAL_PLAN_DRIFT")
    need(data["current_state"]["owner_approval_present"] is False
         and data["explicit_separate_owner_consent"]["approved"] is False,
         "OWNER_APPROVAL_IS_NOT_PRESENT")
    need(data["four_role_experiment_plan"]["max_total_create_ref_posts"]==2
         and data["four_role_experiment_plan"]["max_retries"]==0,
         "POST_OR_RETRY_BUDGET_EXPANDED")
    need(data["trial"]["ruleset_not_admin_irrevocable"] is True,
         "ADMIN_RULESET_MUTABILITY_NOT_ACKNOWLEDGED")
    verify_no_write_source()
    # Revalidate predecessor; this is a SEPARATE snapshot, not a live attestation.
    old=witness.review()
    need(old["classification"]==
         "SEPARATE_READ_SNAPSHOT_COMPATIBLE_NOT_SAME_RUN_BYPASS_PROOF"
         and old["write_authorized"] is False
         and old["bypass_at_original_actions_run_proven"] is False,
         "PREDECESSOR_EVIDENCE_PROMOTED")
    return True

def review():
    frozen=json.loads(CONTRACT.read_text(encoding="utf-8"))
    verify(frozen)
    result={
        "rule_of_one":RULE,
        "classification":CLASSIFICATION,
        "manifest_sha256":digest(frozen),
        "source_main_at_review":REVIEWED_MAIN,
        "source_341_run_id":38187628606,
        "source_341_artifact_zip_sha256":PREDECESSOR["task4_341_artifact_zip_sha256"],
        "roles_planned_only":list(ROLES),
        "max_runs_planned_only":PLAN["max_total_workflow_runs"],
        "max_posts_planned_only":PLAN["max_total_create_ref_posts"],
        "max_retries_planned_only":0,
        "explicit_owner_approval_present":False,
        "approved_exact_future_writer_workflow_sha":None,
        "run_time_signed_independent_bypass_attestation":False,
        "independent_custody_attested":False,
        "real_writer_workflow_installed":False,
        "github_write_token_obtained":False,
        "real_github_gets_in_this_review":0,
        "real_github_create_ref_posts_in_this_review":0,
        "real_provider_posts_in_this_review":0,
        "real_cross_run_cas_proven":False,
        "single_use_irrevocability_proven":False,
        "github_ref_write_authorized":False,
        "provider_dispatch":"DENY"
    }
    result["report_sha256"]=digest(result)
    return result

def real_cas_dispatch(*args,**kwargs):
    raise Denied("TASK4_342_NO_REAL_GITHUB_CREATE_REF_DISPATCH_AUTHORIZED")

def main(argv):
    need(len(argv)==2,"EXACT_ONE_REPORT_OUTPUT_REQUIRED")
    dest=Path(argv[1]).resolve()
    need(dest.parent==(ROOT/"results").resolve()
         and dest.name=="task4-342-final-cas-approval-audit-review-only.json"
         and not dest.exists(),"ONLY_NEW_FIXED_OUTPUT_ALLOWED")
    report=review()
    dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print("TASK4_342_FINAL_CAS_APPROVAL_AUDIT_REVIEW_ONLY_NO_WRITE")
    print("TASK4_342_CLASSIFICATION="+report["classification"])
if __name__=="__main__":main(sys.argv)
