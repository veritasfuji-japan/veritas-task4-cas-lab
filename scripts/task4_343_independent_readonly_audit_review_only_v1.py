#!/usr/bin/env python3
"""Task4 #343: offline, SHA-256 pinned independent audit PROTOCOL ONLY.

Does not fetch an external observer, verify an actual signature, authorize
Github writes, or upgrade a previous runner's bypass visibility. Any submitted
runtime receipt remains UNVERIFIED until a separately reviewed external trust
root, cryptographic verifier, live observer and explicit owner approval exist.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from scripts import task4_342_final_cas_approval_audit_review_only_v1 as predecessor
from scripts import task4_330_github_create_ref_candidate_review_only_v1 as writer

CONTRACT=ROOT/"contracts/TASK4_343_INDEPENDENT_READONLY_AUDIT_PROTOCOL_REVIEW_V1.json"
RULE="TASK4_343_INDEPENDENT_OBSERVER_PROVENANCE_AND_RECEIPT_DESIGN_ONLY"
REVIEWED_MAIN="571dee3d5d88945a7098cd667ceae430b234046a"
EXPECTED_CONTRACT_SHA256="fe38243f3152980aa62c09bc3e94f3c319be3ca91f1a8063d071ecadaaaca735"
CLASSIFICATION="INDEPENDENT_AUDIT_PROTOCOL_REVIEW_ONLY_UNIMPLEMENTED_NO_WRITE_AUTHORITY"
FUTURE_WRITER=".github/workflows/task4-330-authorized-create-ref.yml"
REQUIRED_FIELDS=(
    "schema","rule_of_one","repository","repository_id",
    "source_main_at_review","prior_evidence","immutable_trial_tuple",
    "independent_observer_requirements","required_signed_receipt_fields",
    "audit_capture_phases","mandatory_failure_conditions",
    "integrity_and_timing_constraints","design_state"
)

class Denied(ValueError):pass

def need(value,reason):
    if not value:raise Denied(reason)

def canonical(data):
    return json.dumps(data,sort_keys=True,ensure_ascii=False,
        separators=(",",":"),allow_nan=False).encode("utf-8")

def digest(data):
    return hashlib.sha256(canonical(data)).hexdigest()

def verify(data):
    need(type(data) is dict and set(data)==set(REQUIRED_FIELDS),
         "UNREVIEWED_CONTRACT_FIELDS_DENIED")
    need(digest(data)==EXPECTED_CONTRACT_SHA256,
         "FROZEN_AUDIT_PROTOCOL_DIGEST_MISMATCH")
    need(data["schema"]==
         "veritas.task4.independent-readonly-observer-audit-design-only.v1"
         and data["rule_of_one"]==RULE,
         "AUDIT_PROTOCOL_SCOPE_DRIFT")
    need(data["repository"]=="veritasfuji-japan/veritas-task4-cas-lab"
         and type(data["repository_id"]) is int
         and data["repository_id"]==1414228001
         and data["source_main_at_review"]==REVIEWED_MAIN,
         "AUDIT_REPO_AND_SOURCE_SHA_DRIFT")
    prior=data["prior_evidence"]
    need(prior["task4_342_offline_plan_run_id"]==38188332277
         and prior["task4_342_source_sha"]==REVIEWED_MAIN
         and prior["same_run_bypass_proven"] is False
         and prior["real_cas_proven"] is False,
         "UNPROVEN_PREDECESSOR_PROMOTED")
    plan=data["immutable_trial_tuple"]
    need(plan["allowed_writer_roles"]==["A","B"]
         and plan["nonwriter_roles"]==["PREFLIGHT","C"]
         and plan["planned_max_create_ref_post_count"]==2
         and plan["planned_max_per_writer_post_count"]==1
         and plan["planned_max_retries"]==0,
         "TRIAL_CAP_OR_ROLE_DRIFT")
    spec=data["independent_observer_requirements"]
    need(spec["read_only_observer_capability_only"] is True
         and spec["independent_key_custody_outside_target_repo"] is True
         and spec["observer_app_or_external_auditor_connected"] is False
         and spec["signature_verification_implemented"] is False
         and spec["signed_observer_attestation_trust_root_pinned"] is False
         and spec["public_verification_key_sha256"] is None
         and spec["observer_identity_attested"] is False
         and spec["credential_scope_attested"] is False
         and spec["observation_time_attested"] is False
         and spec["repo_admin_can_edit_ruleset"] is True,
         "OBSERVER_TRUST_ROOT_UNJUSTIFIABLY_PROMOTED")
    timing=data["integrity_and_timing_constraints"]
    need(timing["max_clock_skew_ms"] is None
         and timing["max_capture_age_before_post_ms"] is None
         and timing["max_audit_capture_lag_ms"] is None
         and timing["thresholds_owner_approved"] is False,
         "UNREVIEWED_OBSERVER_TIMING_THRESHOLDS")
    state=data["design_state"]
    need(state["independent_receipt_count"]==0
         and state["consent_for_github_write"] is False
         and state["writer_workflow_installed"] is False
         and state["real_github_create_ref_posts"]==0
         and state["provider_api_posts"]==0
         and state["real_cross_run_cas_proven"] is False
         and state["admin_irrevocable_single_use_proven"] is False
         and state["provider_dispatch"]=="DENY"
         and state["classification"]==CLASSIFICATION,
         "WRITER_DISPATCH_OR_VERIFICATION_AUTHORITY_NOT_GRANTED")
    need(writer.REAL_GITHUB_WRITE_SOURCE_GATE is False
         and writer.APPROVED_WORKFLOW_HEAD_SHA is None
         and writer.LIVE_PROVIDER_DISPATCH_ALLOWED is False,
         "SOURCE_GATES_MUST_REMAIN_HARD_CLOSED")
    need(not (ROOT/FUTURE_WRITER).exists(),
         "GITHUB_LIVE_WRITER_WORKFLOW_IS_FORBIDDEN")
    # Revalidate predecessor from its frozen manifest only. No HTTP transport.
    old=predecessor.review()
    need(old["classification"]==
         "OFFLINE_FINAL_APPROVAL_AUDIT_PLAN_ONLY_NO_GITHUB_WRITE_AUTHORITY"
         and old["github_ref_write_authorized"] is False
         and old["real_cross_run_cas_proven"] is False,
         "PREDECESSOR_IS_NOT_AN_AUTHORITY_TOKEN")
    return True

def assess_future_signed_receipt(*,receipt=None,trust_root=None):
    """Deliberately never verifies a runtime witness in this reviewed revision."""
    raise Denied("INDEPENDENT_SIGNATURE_TRUST_ROOT_AND_OBSERVER_NOT_INSTALLED")

def attempt_real_create_ref(*args,**kwargs):
    raise Denied("TASK4_343_NO_REAL_GITHUB_CREATE_REF_AUTHORIZED")

def review():
    manifest=json.loads(CONTRACT.read_text(encoding="utf-8"))
    verify(manifest)
    out={
        "rule_of_one":RULE,
        "classification":CLASSIFICATION,
        "manifest_sha256":digest(manifest),
        "prior_run_342_id":38188332277,
        "prior_artifact_zip_sha256":
            manifest["prior_evidence"]["task4_342_zip_sha256"],
        "signed_receipt_schema_fields_frozen":
            len(manifest["required_signed_receipt_fields"]),
        "capture_phases_planned":
            len(manifest["audit_capture_phases"]),
        "independent_observer_connected":False,
        "external_observer_credential_scope_verified":False,
        "cryptographic_signature_verification_implemented":False,
        "trust_root_public_key_pinned":False,
        "real_signed_receipts_observed":0,
        "same_run_signed_ruleset_bypass_attested":False,
        "clock_skew_or_capture_lag_approved":False,
        "admin_irrevocability_proven":False,
        "real_cross_run_cas_proven":False,
        "github_write_authorized":False,
        "real_github_get_count_in_this_review":0,
        "real_github_create_ref_posts_in_this_review":0,
        "real_provider_posts_in_this_review":0,
        "provider_dispatch":"DENY"
    }
    out["report_sha256"]=digest(out)
    return out

def main(argv):
    need(len(argv)==2,"EXACT_ONE_REPORT_PATH_REQUIRED")
    dest=Path(argv[1]).resolve()
    need(dest.parent==(ROOT/"results").resolve()
         and dest.name=="task4-343-independent-readonly-audit-design-review-only.json"
         and not dest.exists(),"ONLY_FRESH_FIXED_OUTPUT_ALLOWED")
    report=review()
    dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n",
                    encoding="utf-8")
    print("TASK4_343_INDEPENDENT_OBSERVER_PROTOCOL_FROZEN_DESIGN_ONLY")
    print("TASK4_343_CLASSIFICATION="+report["classification"])
if __name__=="__main__":main(sys.argv)
