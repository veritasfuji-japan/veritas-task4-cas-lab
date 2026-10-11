#!/usr/bin/env python3
"""Task4 #336 staged template and authorization boundary review, no real GitHub calls."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from scripts import task4_330_github_create_ref_candidate_review_only_v1 as parent
from scripts import task4_335_ruleset_prewrite_candidate_review_only_v1 as prior
from scripts import task4_333_github_readonly_prestate_review_only_v1 as guard

RULE="TASK4_336_STAGED_FOUR_ROLE_WORKFLOW_IS_NEVER_AN_EXECUTABLE_WRITER"
REPO="veritasfuji-japan/veritas-task4-cas-lab"
BASE="dd047ed08b556fbd2505a6d6f93d5ed715dc3ce8"
REF="refs/heads/offline-test-ledger/task4-329-de45893cb289d9bca20ab879ac6d2f73"
TARGET="9edd28eee24da559fc0ad24fd97291944acc2ed4"
TEMPLATE="docs/templates/task4-336-four-role-create-ref-STAGED-NOT-INSTALLED.yml"
DEST=".github/workflows/task4-330-authorized-create-ref.yml"
CONTRACT=ROOT/"contracts/TASK4_336_FOUR_ROLE_WORKFLOW_STAGED_REVIEW_V1.json"
WRITE_GATE=False
APPROVED_WORKFLOW_SHA=None
PROVIDER_DISPATCH_ALLOWED=False

class Denied(ValueError):pass

def need(ok,message):
    if not ok:raise Denied(message)

def canonical(data):
    return json.dumps(data,sort_keys=True,ensure_ascii=False,
                      separators=(",",":"),allow_nan=False).encode("utf-8")

def digest(data):return hashlib.sha256(canonical(data)).hexdigest()

def expected_contract():
    return {
      "schema":"veritas.task4.future-github-create-ref-four-role-template-review.v1",
      "rule_of_one":RULE,
      "base_reviewed_main_sha":BASE,"repo":REPO,"visibility":"public",
      "ruleset_id":24880024,
      "ruleset_last_reviewed_updated_at":"2026-10-11T22:00:45.379+09:00",
      "frozen_ref":REF,"frozen_target":TARGET,
      "staged_template_path":TEMPLATE,
      "proposed_install_path":DEST,
      "roles":["PREFLIGHT","A","B","C"],
      "future_max_distinct_runs":4,
      "future_max_writer_post_count":2,
      "future_max_posts_per_writer_run":1,
      "retry_count":0,
      "automatic_redispatch_allowed":False,
      "proposed_runner":"ubuntu-24.04",
      "timeout_minutes_per_run":8,
      "proposed_total_runner_minutes_ceiling":32,
      "trial_ref_protection_rules":["deletion","non_fast_forward","update"],
      "ruleset_bypass_actors":[],"ruleset_enforcement":"active",
      "concurrent_a_b_interleaving_attested":False,
      "no_actions_concurrency_serializing_writers":True,
      "workflow_template_installed":False,
      "workflow_template_jobs_enabled":False,
      "git_contents_write_workflow_installed":False,
      "old_source_writer_gate_enabled":False,
      "owner_future_write_approval":None,
      "frozen_approved_writer_run_head_sha":None,
      "future_source_pin_issuance_stage":"POST_MERGE_EXTERNAL_OWNER_APPROVAL_ONLY",
      "future_preflight_against_current_github_required":True,
      "future_c_audit_distinct_job_required":True,
      "future_422_conflict_requires_independent_corrobation":True,
      "existing_provider_dispatch":"DENY",
      "github_real_create_posts_in_this_pr":0,
      "provider_posts_in_this_pr":0,
      "actual_bank_effects_in_this_pr":0,
      "real_github_cas_proven":False,
      "immutable_single_use_authority_proven":False,
      "state":"REVIEW_STAGED_ONLY_NO_WRITE_AUTHORITY"
    }

def verify_contract(data):
    want=expected_contract()
    need(type(data) is dict and set(data)==set(want),
         "EXACT_REVIEWED_CONTRACT_SCHEMA_REQUIRED")
    for key,val in want.items():
        need(type(data[key]) is type(val) and data[key]==val,
             "CONTRACT_SCOPE_OR_AUTHORITY_DRIFT_"+key)
    need(parent.proposed_request()=={"ref":REF,"sha":TARGET},
         "PARENT_FIXED_REQUEST_CHANGED")
    return True

def verify_template(text):
    need(type(text) is str and text.startswith(
         "# TASK4 #336 — STAGED FUTURE DESIGN. NOT INSTALLED IN .github/workflows.\n"),
         "STAGED_UNINSTALLED_HEADER_REQUIRED")
    need(text.count("    if: ${{ false }}")==3,
         "ALL_THREE_FUTURE_JOB_GATES_MUST_BE_LITERAL_FALSE")
    need(text.count("          exit 78")==3,
         "ALL_THREE_STAGED_STEPS_MUST_ABORT")
    need(text.count("      contents: write")==1,
         "EXACTLY_ONE_FUTURE_WRITER_JOB_SCOPED_PERMISSION")
    need(text.count("      contents: read")==2 and
         "permissions:\n  contents: read\n" in text,
         "READ_ONLY_GLOBAL_AND_OTHER_ROLES")
    need(text.count("    runs-on: ubuntu-24.04")==3,
         "EXACT_THREE_STANDARD_HOSTED_JOBS")
    need(text.count("    timeout-minutes: 8")==3,
         "EIGHT_MINUTE_PER_JOB_BOUND")
    need(text.count("persist-credentials: false")==3,
         "NO_PERSISTED_CHECKOUT_CREDENTIALS")
    need(text.count("      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262")==3,
         "THIRD_PARTY_ACTION_MUST_BE_EXACT_SHA_PINNED")
    need("on:\n  workflow_dispatch:\n" in text,
         "MANUAL_ONLY_CANDIDATE_REQUIRED")
    for role in ("PREFLIGHT","A","B","C"):
        need("          - "+role+"\n" in text,
             "MISSING_FUTURE_ROLE_"+role)
    for role in ("readonly-preflight","writer-once","readonly-audit"):
        need("  "+role+":\n" in text,"MISSING_FUTURE_JOB_"+role)
    for required in (REF,TARGET,DEST):
        need(required in text,"FROZEN_EXACT_SCOPE_NOT_STAGED")
    for banned in ("pull_request_target:","\n  pull_request:","\n  push:",
                   "\nconcurrency:","\n  concurrency:","secrets.",
                   "github.token","gh api ","curl ","https://api.github.com",
                   "python scripts/task4_330","real_create_ref_once_under_future_authorization"):
        need(banned not in text,"UNSAFE_EXECUTABLE_TEMPLATE_"+banned)
    return True

def review():
    data=json.loads(CONTRACT.read_text(encoding="utf-8"))
    verify_contract(data)
    text=(ROOT/TEMPLATE).read_text(encoding="utf-8")
    verify_template(text)
    guard.verify_gates()
    prior.verify_no_write()
    need(WRITE_GATE is False and APPROVED_WORKFLOW_SHA is None
         and PROVIDER_DISPATCH_ALLOWED is False,
         "TASK4_336_WRITER_STAYS_HARD_OFF")
    need(parent.REAL_GITHUB_WRITE_SOURCE_GATE is False
         and parent.APPROVED_WORKFLOW_HEAD_SHA is None
         and parent.LIVE_PROVIDER_DISPATCH_ALLOWED is False,
         "PARENT_GATES_STAY_HARD_OFF")
    need(not (ROOT/DEST).exists(),
         "UNAUTHORIZED_ACTIVE_WRITER_WORKFLOW")
    result={
      "rule_of_one":RULE,
      "classification":"STAGED_TEMPLATE_OFFLINE_VALID_NOT_AN_ACTIVE_WORKFLOW",
      "manifest_sha256":digest(data),
      "staged_template_sha256":hashlib.sha256(text.encode("utf-8")).hexdigest(),
      "fixed_request_sha256":digest(parent.proposed_request()),
      "staged_jobs_all_hard_disabled":True,
      "real_writer_workflow_present":False,
      "actual_github_write_posts":0,"provider_posts":0,
      "real_cas_proven":False,"future_source_sha_approved":False,
      "owner_real_github_write_consent_present":False,
      "provider_dispatch":"DENY"
    }
    result["report_sha256"]=digest(result)
    return result

def staged_write_once(*args,**kwargs):
    raise Denied("TASK4_336_NO_REAL_GITHUB_WRITE_GATE")

def main(argv):
    need(len(argv)==2,"ONE_FIXED_LOCAL_REPORT")
    path=Path(argv[1]).resolve()
    need(path.parent==(ROOT/"results").resolve()
         and path.name=="task4-336-staged-workflow-review.json"
         and not path.exists(),"NO_REDIRECT_OR_REPORT_OVERWRITE")
    r=review()
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(r,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print("TASK4_336_STAGED_WRITER_WORKFLOW_NOT_INSTALLED_ZERO_REAL_POSTS")

if __name__=="__main__":main(sys.argv)
