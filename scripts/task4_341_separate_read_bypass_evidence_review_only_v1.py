#!/usr/bin/env python3
"""Task4 #341: verify two differently scoped read observations OFFLINE ONLY.

One authenticated GitHub Actions READ token observed a Ruleset WITHOUT
bypass_actors. A separate connected-GitHub REST GET observed [] bypass actors.
Do NOT conflate those distinct principals/times, or grant writing authority.
No HTTP transport or API tokens in this file; no GitHub CreateRef or Provider.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
from scripts import task4_338_live_authenticated_readonly_preflight_v1 as live
from scripts import task4_335_ruleset_prewrite_candidate_review_only_v1 as rules
from scripts import task4_332_cas_pre_dispatch_authorization_review_only_v1 as guard
from scripts import task4_330_github_create_ref_candidate_review_only_v1 as writer

CONTRACT=ROOT/"contracts/TASK4_341_SEPARATE_READ_BYPASS_EVIDENCE_FREEZE_V1.json"
RULE="TASK4_341_SEPARATE_GITHUB_READ_PATH_BYPASS_EVIDENCE_NEVER_RUNTIME_AUTHORITY"
RUN_HEAD="cd1d137da8af98620ddd59f9adc1bee889128955"
ZIP_SHA="51e4af5d773b2c158cc128b45b1bb2501980d84c6e10b37aae4526be0c550a34"
REPORT_SHA="adb10902ff7868ee631117e08471cf90900192429055425ccd1a2d544444f947"
CANONICAL_SHA="ec6be5f09a67b3dabbde4dd419e0872ee93e478ed3dfc2ca501bf2b6d04d7a71"
STATUS="SEPARATE_READ_SNAPSHOT_COMPATIBLE_NOT_SAME_RUN_BYPASS_PROOF"

class Denied(ValueError): pass

def need(ok,why):
    if not ok: raise Denied(why)

def canonical(value):
    return json.dumps(value,sort_keys=True,ensure_ascii=False,
                      separators=(",",":"),allow_nan=False).encode("utf-8")

def sha_bytes(value): return hashlib.sha256(value).hexdigest()
def digest(value): return sha_bytes(canonical(value))

def exact_dict(value,names,code):
    need(type(value) is dict and set(value)==set(names),code)

def verify(data):
    keys={
        "schema","rule_of_one","repository","repository_id","frozen_source_main_sha",
        "source_run_id","source_job_id","source_run_attempt","source_run_conclusion",
        "source_artifact_id","source_artifact_size_bytes","source_artifact_zip_sha256",
        "source_report_file_sha256","source_junit_testcases","source_run_report",
        "separate_ruleset_observation","bridge_claims"
    }
    exact_dict(data,keys,"NON_CANONICAL_FREEZE_FIELDS")
    required={
        "schema":"veritas.task4.separate-read-ruleset-bypass-evidence-freeze.v1",
        "rule_of_one":RULE,"repository":live.REPO,
        "repository_id":live.REPO_ID,
        "frozen_source_main_sha":RUN_HEAD,
        "source_run_id":38186765875,
        "source_job_id":114610648509,
        "source_run_attempt":1,
        "source_run_conclusion":"success",
        "source_artifact_id":11719338461,
        "source_artifact_size_bytes":7184,
        "source_artifact_zip_sha256":ZIP_SHA,
        "source_report_file_sha256":REPORT_SHA,
        "source_junit_testcases":302
    }
    for key,value in required.items():
        need(type(data[key]) is type(value) and data[key]==value,
             "UNREVIEWED_SOURCE_METADATA_"+key)

    r=data["source_run_report"]
    need(type(r) is dict and type(r.get("report_sha256")) is str,
         "FROZEN_REPORT_OBJECT_REQUIRED")
    need(r["report_sha256"]==CANONICAL_SHA,
         "FROZEN_RUN_CANONICAL_SHA_REQUIRED")
    unsigned={k:v for k,v in r.items() if k!="report_sha256"}
    need(digest(unsigned)==CANONICAL_SHA,"RUN_REPORT_CANONICAL_DIGEST_CHANGED")
    exact_render=(json.dumps(r,indent=2,sort_keys=True,ensure_ascii=True)+"\\n").encode("utf-8")
    need(sha_bytes(exact_render)==REPORT_SHA,
         "EXACT_RUN_REPORT_FILE_BYTES_DIFFER")
    expected_report={
        "run_id":"38186765875","head_sha":RUN_HEAD,
        "event":"workflow_dispatch","actual_authenticated_get_count":5,
        "verification_outcome":"PASS_READONLY_ONLY",
        "failure_code":None,"provider_dispatch":"DENY",
        "future_writer_authorized":False,
        "github_write_permission_granted":False,
        "real_github_create_ref_post_count":0,"real_provider_post_count":0,
        "read_response_body_persisted":False,
        "approval_token_persisted":False,
        "ruleset_static_drift_fields":[],
        "source":"AUTHENTICATED_GITHUB_HOSTED_ACTIONS_GET",
        "workflow_ref":live.REPO+"/.github/workflows/"+live.WORKFLOW+"@refs/heads/main",
        "rule_of_one":live.RULE
    }
    for key,value in expected_report.items():
        need(key in r and type(r[key]) is type(value) and r[key]==value,
             "SOURCE_REPORT_BOUNDARY_"+key)
    need(r.get("http_statuses")==dict(live.parent.STATUSES),
         "LIVE_FIVE_HTTP_STATUSES_REQUIRED")
    need(r.get("exact_get_paths")==[live.parent.PATHS[k] for k in live.KEYS],
         "LIVE_EXACT_GET_SCOPE_REQUIRED")
    hashes=r.get("body_sha256")
    exact_dict(hashes,live.KEYS,"SOURCE_BODY_HASH_SET_INVALID")
    need(all(type(v) is str and len(v)==64 and
             all(c in "0123456789abcdef" for c in v)
             for v in hashes.values()),"SOURCE_BODY_DIGEST_FORMAT_INVALID")
    verdict=r.get("verdict")
    exact_dict(verdict,{
        "admin_can_modify_ruleset_not_excluded","all_five_expected_http_statuses",
        "classification","current_actor_bypass_visible",
        "observed_ref_missing_at_this_instant","real_cross_run_cas_proven",
        "ruleset_bypass_list_visible","ruleset_full_bypass_verified",
        "ruleset_updated_at_exact_instant_verified",
        "ruleset_updated_at_text_format_differs","write_authorized"
    },"SOURCE_RUN_VERDICT_FIELDS_INVALID")
    expected_v={
        "classification":"FIVE_LIVE_GETS_BYPASS_VISIBILITY_INCOMPLETE",
        "ruleset_bypass_list_visible":False,
        "current_actor_bypass_visible":True,
        "ruleset_full_bypass_verified":False,
        "ruleset_updated_at_exact_instant_verified":True,
        "ruleset_updated_at_text_format_differs":True,
        "observed_ref_missing_at_this_instant":True,
        "all_five_expected_http_statuses":True,
        "admin_can_modify_ruleset_not_excluded":True,
        "write_authorized":False,"real_cross_run_cas_proven":False
    }
    for key,value in expected_v.items():
        need(type(verdict[key]) is type(value) and verdict[key]==value,
             "SOURCE_VERDICT_CANNOT_BE_PROMOTED_"+key)

    w=data["separate_ruleset_observation"]
    exact_dict(w,{"api_url","method","observation_timestamp_attested",
                  "raw_response_signed","observer_token_scope_attested",
                  "same_runner_as_source","same_instant_as_source_attested",
                  "ruleset_projection"},"SEPARATE_WITNESS_FIELDS_INVALID")
    base_path="https://api.github.com/repos/"+live.REPO+"/rulesets/"+str(live.RULESET_ID)
    need(w["api_url"]==base_path and w["method"]=="CONNECTED_GITHUB_REST_GET",
         "SEPARATE_REST_ORIGIN_UNSUPPORTED")
    for k in ("observation_timestamp_attested","raw_response_signed",
              "observer_token_scope_attested","same_runner_as_source",
              "same_instant_as_source_attested"):
        need(type(w[k]) is bool and w[k] is False,
             "UNATTESTED_INDEPENDENCE_MUST_NOT_BE_PROMOTED_"+k)
    witness=w["ruleset_projection"]
    expected=rules.expected_ruleset()
    exact_dict(witness,expected,"WITNESS_RULESET_PROJECTION_FIELDS_INVALID")
    for key,value in expected.items():
        need(type(witness[key]) is type(value) and witness[key]==value,
             "WITNESS_FROZEN_RULESET_DRIFT_"+key)
    need(live.same_exact_instant(witness["updated_at"],live.RULESET_UPDATED_AT),
         "WITNESS_FROZEN_UTC_INSTANT_CHANGED")
    need(witness["bypass_actors"]==[]
         and witness["current_user_can_bypass"]=="never",
         "SEPARATE_BYPASS_FIELDS_NOT_SAFE_AT_SNAPSHOT")

    claims=data["bridge_claims"]
    want={
        "independent_ruleset_field_snapshot_recorded":True,
        "common_field_compatibility_checked_offline":True,
        "raw_ruleset_http_body_digest_reconstructable":False,
        "source_runner_bypass_list_observed":False,
        "separate_observer_bypass_list_observed":True,
        "runtime_no_bypass_attested":False,
        "independent_admin_custody_attested":False,
        "authorization_at_execution_attested":False,
        "real_github_post_count":0,
        "real_provider_post_count":0,
        "real_cross_run_cas_proven":False,
        "irreversible_single_use_proven":False,
        "future_writer_authorized":False,
        "provider_dispatch":"DENY",
        "classification":STATUS
    }
    exact_dict(claims,want,"UNREVIEWED_BRIDGE_CLAIMS")
    for key,value in want.items():
        need(type(claims[key]) is type(value) and claims[key]==value,
             "UNSUPPORTED_BRIDGE_CLAIM_"+key)

    guard.verify_source_gates()
    need(writer.REAL_GITHUB_WRITE_SOURCE_GATE is False
         and writer.APPROVED_WORKFLOW_HEAD_SHA is None
         and writer.LIVE_PROVIDER_DISPATCH_ALLOWED is False,
         "REAL_WRITER_SOURCE_GATE_NOT_CLOSED")
    need(not (ROOT/".github/workflows/task4-330-authorized-create-ref.yml").exists(),
         "LIVE_GITHUB_REF_WRITER_NOT_PERMITTED")
    return True

def review():
    d=json.loads(CONTRACT.read_text(encoding="utf-8"))
    verify(d)
    result={
        "rule_of_one":RULE,
        "classification":STATUS,
        "manifest_sha256":digest(d),
        "frozen_source_run_id":d["source_run_id"],
        "frozen_source_head_sha":RUN_HEAD,
        "source_artifact_zip_sha256":ZIP_SHA,
        "source_report_sha256":CANONICAL_SHA,
        "separate_ruleset_projection_sha256":digest(
            d["separate_ruleset_observation"]["ruleset_projection"]),
        "source_ruleset_full_raw_body_verified":False,
        "separate_bypass_observed_in_transcribed_snapshot":True,
        "bypass_at_original_actions_run_proven":False,
        "independent_signed_observer_attested":False,
        "external_admin_custody_attested":False,
        "observations_simultaneous_attested":False,
        "offline_evidence_crosschecked":True,
        "actual_github_get_count_in_this_review":0,
        "actual_github_write_count_in_this_review":0,
        "actual_provider_post_count_in_this_review":0,
        "write_authorized":False,
        "real_cross_run_cas_proven":False,
        "provider_dispatch":"DENY"
    }
    result["report_sha256"]=digest(result)
    return result

def main(argv):
    need(len(argv)==2,"EXACT_OUTPUT_ARG_REQUIRED")
    dest=Path(argv[1]).resolve()
    need(dest.parent==(ROOT/"results").resolve()
         and dest.name=="task4-341-separate-read-bypass-offline-review.json"
         and not dest.exists(),"ONLY_FRESH_FIXED_OFFLINE_RESULT_ALLOWED")
    result=review()
    dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(result,sort_keys=True,indent=2)+"\\n",encoding="utf-8")
    print("TASK4_341_TWO_READ_PATHS_SNAPSHOT_ONLY_BYPASS_NOT_RUNTIME_PROVEN")
if __name__=="__main__": main(sys.argv)
