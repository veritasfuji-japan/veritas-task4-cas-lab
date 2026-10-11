#!/usr/bin/env python3
"""#331: OFFLINE-ONLY A/B/C cross-Run evidence schema and strict refusal oracle.

One invariant: candidate one-shot CreateRef + remote GET corroboration cannot
be promoted from incomplete, duplicated, ambiguous or SYNTHETIC receipts.
This program has NO GitHub or Provider API client and DOES NOT authenticate
receipts from GitHub. Synthetic results remain SYNTHETIC even when all checks
pass. Future real cross-host attestation must independently fetch and pin
GitHub run/job/ref facts under separately approved controls.
"""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import re
import sys

from scripts import task4_330_github_create_ref_candidate_review_only_v1 as parent

RULE="TASK4_331_THREE_INDEPENDENT_GITHUB_RUN_RECEIPT_REVIEW_OFFLINE_V1"
ROOT=Path(__file__).resolve().parents[1]
REPO=parent.LAB
LAB_BASE=parent.MERGED_LAB_MAIN
FIXTURE_WORKFLOW_HEAD="40b98037a1cb28362de2ac414c98837409ea686c"
REF=parent.EXPERIMENT_REF
FIXED_TARGET=parent.TARGET_SHA
REF_PATH=parent.GET_PATH
CREATE_PATH=parent.POST_PATH
EXPECTED_ROLES=("PREFLIGHT","A","B","C")
ALLOWED_STATUSES={"PREFLIGHT":404,"A":201,"B":422,"C":200}
RUN_PATTERN=re.compile(r"[1-9][0-9]{7,15}\Z")
JOB_PATTERN=re.compile(r"[1-9][0-9]{7,15}\Z")
HEX64=re.compile(r"[a-f0-9]{64}\Z")
HEX40=re.compile(r"[a-f0-9]{40}\Z")
ALLOWED_ORIGIN="SYNTHETIC_OFFLINE_ONLY"
EVENT="workflow_dispatch"
CLASSIFICATION="SYNTHETIC_A_B_C_SHAPE_VALID_NOT_REAL_GITHUB_CAS_PROOF"

class Denied(ValueError):pass

def need(x,why):
    if not x:raise Denied(why)

def canonical(x):
    return json.dumps(x,sort_keys=True,ensure_ascii=False,
                      separators=(",",":"),allow_nan=False).encode("utf-8")

def sha(x):
    return hashlib.sha256(canonical(x)).hexdigest()

def receipt_fields():
    return {"role","repository","run_id","job_id","attempt","actor",
            "event","workflow_ref","workflow_head_sha","trial_ref",
            "target_commit","origin","request_sha256","http_status",
            "http_payload","http_payload_sha256","receipt_sha256"}

def fixture_receipt(role,run_id,job_id):
    need(role in EXPECTED_ROLES,"ROLE_INVALID")
    status=ALLOWED_STATUSES[role]
    if role=="PREFLIGHT":
        payload={"message":"Not Found"}
    elif role=="A":
        payload={"ref":REF,"object":{"sha":FIXED_TARGET,"type":"commit"}}
    elif role=="B":
        payload={"message":"Reference already exists",
                 "errors":[{"code":"already_exists","resource":"Reference"}]}
    else:
        payload={"ref":REF,"object":{"sha":FIXED_TARGET,"type":"commit"}}
    out={
      "role":role,"repository":REPO,"run_id":run_id,
      "job_id":job_id,"attempt":1,"actor":"veritasfuji-japan",
      "event":EVENT,"workflow_ref":"refs/heads/main",
      "workflow_head_sha":FIXTURE_WORKFLOW_HEAD,
      "trial_ref":REF,"target_commit":FIXED_TARGET,
      "origin":ALLOWED_ORIGIN,
      "request_sha256":sha(parent.proposed_request()) if role in ("A","B")
                        else sha({"GET":REF_PATH}),
      "http_status":status,"http_payload":payload,
      "http_payload_sha256":sha(payload)
    }
    out["receipt_sha256"]=sha(out)
    return out

def synthetic_bundle():
    return {
      "rule_of_one":RULE,"evidence_class":"SYNTHETIC_TEST_ONLY",
      "lab_repository":REPO,"exact_candidate_ref":REF,
      "exact_target_commit":FIXED_TARGET,"planned_create_path":CREATE_PATH,
      "planned_readback_path":REF_PATH,
      "source_gate_still_closed":True,
      "actual_github_ref_writes":0,
      "actual_independent_github_actions_runs":0,
      "actual_openai_posts":0,
      "provider_dispatch":"DENY",
      "receipts":[
          fixture_receipt("PREFLIGHT","38139000001","114490000001"),
          fixture_receipt("A","38139000002","114490000002"),
          fixture_receipt("B","38139000003","114490000003"),
          fixture_receipt("C","38139000004","114490000004")
      ]
    }

def validate_bundle(bundle):
    need(type(bundle) is dict and set(bundle)=={
        "rule_of_one","evidence_class","lab_repository",
        "exact_candidate_ref","exact_target_commit","planned_create_path",
        "planned_readback_path","source_gate_still_closed",
        "actual_github_ref_writes","actual_independent_github_actions_runs",
        "actual_openai_posts","provider_dispatch","receipts"},
        "BUNDLE_EXACT_SCHEMA_REQUIRED")
    for field,value in (
        ("rule_of_one",RULE),("evidence_class","SYNTHETIC_TEST_ONLY"),
        ("lab_repository",REPO),("exact_candidate_ref",REF),
        ("exact_target_commit",FIXED_TARGET),
        ("planned_create_path",CREATE_PATH),
        ("planned_readback_path",REF_PATH),
        ("source_gate_still_closed",True),
        ("actual_github_ref_writes",0),
        ("actual_independent_github_actions_runs",0),
        ("actual_openai_posts",0),
        ("provider_dispatch","DENY")):
        need(type(bundle[field]) is type(value) and bundle[field]==value,
             "SYNTHETIC_BUNDLE_SCOPE_OR_AUTHORITY_DRIFT_"+field)
    receipts=bundle["receipts"]
    need(type(receipts) is list and len(receipts)==4,
         "EXACTLY_FOUR_DISTINCT_SYNTHETIC_RUNS_REQUIRED")
    need(parent.REAL_GITHUB_WRITE_SOURCE_GATE is False and
         parent.APPROVED_WORKFLOW_HEAD_SHA is None,
         "PARENT_LIVE_GITHUB_REF_WRITER_MUST_REMAIN_OFF")
    observed_runs=set()
    observed_jobs=set()
    for idx,role in enumerate(EXPECTED_ROLES):
        p=receipts[idx]
        need(type(p) is dict and set(p)==receipt_fields(),
             "RECEIPT_EXACT_FIELDS_REQUIRED")
        without=dict(p)
        claimed=without.pop("receipt_sha256")
        need(type(claimed) is str and HEX64.fullmatch(claimed)
             and sha(without)==claimed,"RECEIPT_HASH_MISMATCH")
        payload=p["http_payload"]
        need(type(payload) is dict and
             type(p["http_payload_sha256"]) is str and
             HEX64.fullmatch(p["http_payload_sha256"]) is not None and
             p["http_payload_sha256"]==sha(payload),
             "HTTP_PAYLOAD_SHA_MISMATCH")
        for field,value in (
            ("role",role),("repository",REPO),("attempt",1),
            ("actor","veritasfuji-japan"),("event",EVENT),
            ("workflow_ref","refs/heads/main"),
            ("workflow_head_sha",FIXTURE_WORKFLOW_HEAD),
            ("trial_ref",REF),("target_commit",FIXED_TARGET),
            ("origin",ALLOWED_ORIGIN),("http_status",ALLOWED_STATUSES[role]),
            ("request_sha256",sha(parent.proposed_request()) if role in ("A","B")
             else sha({"GET":REF_PATH}))):
            need(type(p[field]) is type(value) and p[field]==value,
                 "RECEIPT_FROZEN_FIELD_MISMATCH_"+field)
        run=p["run_id"];job=p["job_id"]
        need(type(run) is str and RUN_PATTERN.fullmatch(run) is not None
             and run not in observed_runs,"RUN_ID_NONUNIQUE_OR_INVALID")
        need(type(job) is str and JOB_PATTERN.fullmatch(job) is not None
             and job not in observed_jobs,"JOB_ID_NONUNIQUE_OR_INVALID")
        observed_runs.add(run);observed_jobs.add(job)
        if role=="PREFLIGHT":
            need(payload=={"message":"Not Found"},
                 "ONLY_SYNTHETIC_MISSING_REF_PRESTATE_ACCEPTED")
        elif role in ("A","C"):
            need(payload=={"ref":REF,"object":{"sha":FIXED_TARGET,"type":"commit"}},
                 "GIT_REF_IDENTITY_AND_TARGET_MUST_MATCH")
        else:
            # A 422 ALONE is not enough: require this EXACT synthetic
            # annotated collision, still never call it actual GitHub proof.
            need(payload=={"message":"Reference already exists",
                           "errors":[{"code":"already_exists",
                                      "resource":"Reference"}]},
                 "422_ONLY_NOT_PROOF_OF_DUPLICATE")
    return {
       "rule_of_one":RULE,
       "classification":CLASSIFICATION,
       "synthetic_receipts_validated":4,
       "distinct_synthetic_run_ids":4,
       "distinct_synthetic_job_ids":4,
       "simulated_create_201":1,
       "simulated_duplicate_422":1,
       "simulated_separate_readback_200":1,
       "independent_real_github_api_evidence":False,
       "real_github_cross_run_cas_proven":False,
       "real_provider_dispatch_allowed":False,
       "real_github_ref_writes":0,
       "provider_posts":0,
       "evidence_bundle_sha256":sha(bundle)
    }

def emit_local_result(path):
    dest=Path(path).resolve()
    need(dest.parent==(ROOT/"results").resolve() and
         dest.name=="task4-331-offline-ab-c-receipt-report.json" and
         not dest.exists(),"NEW_EXACT_LOCAL_REPORT_ONLY")
    record=validate_bundle(synthetic_bundle())
    result={"rule_of_one":RULE,"evidence_class":"SYNTHETIC_ONLY",
            "validator_result":record,"sample_receipts":synthetic_bundle(),
            "real_github_dispatch":False,"real_provider_dispatch":False}
    result["report_sha256"]=sha(result)
    dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n",
                    encoding="utf-8")
    return result

if __name__=="__main__":
    need(len(sys.argv)==2,"USAGE: ab-c-receipt.py results/...")
    report=emit_local_result(sys.argv[1])
    need(report["validator_result"]["real_github_cross_run_cas_proven"] is False,
         "NO_SYNTHETIC_TO_REAL_PROMOTION")
    print("TASK4_331_SYNTHETIC_AB_C_EVIDENCE_ONLY_REAL_GITHUB_NOT_TESTED")
