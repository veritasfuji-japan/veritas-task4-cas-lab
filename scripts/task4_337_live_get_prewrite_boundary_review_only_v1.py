#!/usr/bin/env python3
"""Task4 #337: five-exact-GET future prewrite boundary candidate, hard disabled.

The fixture is synthetic. The reusable GET shape checker is strict and
read-only; its success is NEVER an approval or a live GitHub attestation.
The optional HTTPS transport is SOURCE-GATED CLOSED, cannot send POST, and is
NEVER invoked from CI/CLI. A future explicit SHA-scoped authorization and
a separate PR are required to install/activate the real writer.
"""
from __future__ import annotations
import hashlib
from http.client import HTTPSConnection,HTTPException
import json
from pathlib import Path
import re
import ssl
import sys

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from scripts import task4_330_github_create_ref_candidate_review_only_v1 as parent
from scripts import task4_335_ruleset_prewrite_candidate_review_only_v1 as rules
from scripts import task4_336_future_workflow_staged_review_only_v1 as staged

RULE="TASK4_337_FIVE_EXACT_GET_PREFLIGHT_FAIL_CLOSED_WITHOUT_POST_AUTHORIZATION"
REVIEW_MAIN="03cc2f9f340605c32f16fd328ac18389fe64639b"
REPO="veritasfuji-japan/veritas-task4-cas-lab"
REPO_ID=1414228001
REF="refs/heads/offline-test-ledger/task4-329-de45893cb289d9bca20ab879ac6d2f73"
TARGET="9edd28eee24da559fc0ad24fd97291944acc2ed4"
RULESET_ID=24880024
RULESET_UPDATED_AT="2026-10-11T22:00:45.379+09:00"
GITHUB_HOST="api.github.com"
HEX40=re.compile(r"[a-f0-9]{40}")
PATHS={
    "repository":"/repos/"+REPO,
    "main":"/repos/"+REPO+"/commits/main",
    "target":"/repos/"+REPO+"/git/commits/"+TARGET,
    "ruleset":"/repos/"+REPO+"/rulesets/"+str(RULESET_ID),
    "candidate":"/repos/"+REPO+"/git/ref/"+REF.removeprefix("refs/"),
}
STATUSES={"repository":200,"main":200,"target":200,"ruleset":200,"candidate":404}
ORDER=("repository","main","target","ruleset","candidate")
CONTRACT=ROOT/"contracts/TASK4_337_GITHUB_FIVE_GET_PREWRITE_BOUNDARY_REVIEW_V1.json"
ACTIVE_WRITER_WORKFLOW=ROOT/".github/workflows/task4-330-authorized-create-ref.yml"
# Both gates are source-code literals. No environment variable activates them.
LIVE_READONLY_NETWORK_GATE=False
REAL_GITHUB_WRITE_SOURCE_GATE=False
EXTERNALLY_APPROVED_WORKFLOW_SHA=None
PROVIDER_DISPATCH_ALLOWED=False

class Denied(ValueError):pass

def need(value,why):
    if not value:raise Denied(why)

def canonical(x):
    return json.dumps(x,sort_keys=True,ensure_ascii=False,
                      separators=(",",":"),allow_nan=False).encode("utf-8")

def sha(x):return hashlib.sha256(canonical(x)).hexdigest()

def expected_contract():
    return {
        "schema":"veritas.task4.real-github-get-prewrite-boundary-review-only.v1",
        "rule_of_one":RULE,
        "reviewed_main_sha":REVIEW_MAIN,
        "repository_full_name":REPO,
        "repository_id":REPO_ID,
        "repository_visibility":"public",
        "repository_default_branch":"main",
        "candidate_ref":REF,"target_commit":TARGET,
        "ruleset_id":RULESET_ID,"ruleset_updated_at":RULESET_UPDATED_AT,
        "github_api_host":GITHUB_HOST,
        "api_paths":PATHS,"api_method":"GET",
        "expected_http_statuses":STATUSES,
        "observed_protection_rules":["deletion","non_fast_forward","update"],
        "observed_bypass_actors":[],
        "live_readonly_network_gate":False,
        "live_create_ref_write_gate":False,
        "separately_approved_workflow_sha":None,
        "signed_owner_approval_reference":None,
        "authorized_workflow_installed":False,
        "role_a_b_writer_attempts_executed":0,
        "actual_github_get_count":0,
        "actual_github_post_count":0,
        "actual_provider_post_count":0,
        "current_run_identity_attested":False,
        "candidate_absence_attested_for_future_runtime":False,
        "github_actions_final_writer_sha_frozen":False,
        "proof_class":"SYNTHETIC_OFFLINE_GET_REPLIES_ONLY",
        "provider_dispatch":"DENY",
        "real_cross_run_cas_proven":False,
        "status":"PREWRITE_REVIEW_ONLY_NEVER_AUTHORIZES_CREATE_REF"
    }

def verify_contract(m):
    want=expected_contract()
    need(type(m) is dict and set(m)==set(want),"EXACT_CONTRACT_KEYS_REQUIRED")
    for key,value in want.items():
        need(type(m[key]) is type(value) and m[key]==value,
             "UNREVIEWED_CONTRACT_DRIFT_"+key)
    return True

def synthetic_get_fixture(*,expected_head=REVIEW_MAIN):
    """Local test fixture. No claim of observed GitHub HTTPS traffic."""
    return {
        "repository":{"status":200,"body":{
            "id":REPO_ID,"full_name":REPO,"visibility":"public",
            "private":False,"default_branch":"main"}},
        "main":{"status":200,"body":{"sha":expected_head}},
        "target":{"status":200,"body":{"sha":TARGET}},
        "ruleset":{"status":200,"body":rules.expected_ruleset()},
        "candidate":{"status":404,"body":{"message":"Not Found"}}
    }

def verify_five_exact_gets(responses,*,expected_head):
    """Validate untrusted candidate REST replies; no authorization returned.

    Future code must separately prove the TLS issuer, token, runner and
    runtime capture, and must recheck on each role immediately before POST.
    """
    need(type(expected_head) is str and HEX40.fullmatch(expected_head),
         "EXTERNAL_EXACT_HEAD_SHA_REQUIRED")
    need(type(responses) is dict and set(responses)==set(ORDER),
         "EXACT_FIVE_GET_RESPONSES_REQUIRED")
    for key in ORDER:
        item=responses[key]
        need(type(item) is dict and set(item)=={"status","body"},
             "MALFORMED_GET_RECEIPT_"+key)
        need(type(item["status"]) is int and item["status"]==STATUSES[key],
             "UNEXPECTED_HTTP_STATUS_"+key)
        need(type(item["body"]) is dict,"MALFORMED_GET_BODY_"+key)
    repo=responses["repository"]["body"]
    need(type(repo.get("id")) is int and repo["id"]==REPO_ID
         and repo.get("full_name")==REPO
         and repo.get("visibility")=="public"
         and repo.get("private") is False
         and repo.get("default_branch")=="main",
         "WRONG_REPOSITORY_OR_VISIBILITY")
    main=responses["main"]["body"]
    need(main.get("sha")==expected_head,"MAIN_HEAD_PIN_MISMATCH")
    target=responses["target"]["body"]
    need(target.get("sha")==TARGET,"EXISTING_TARGET_MISMATCH")
    try:
        rules.require_frozen_ruleset(responses["ruleset"]["body"])
    except rules.Denied as exc:
        raise Denied("RULESET_PREWRITE_NOT_FROZEN") from exc
    ref=responses["candidate"]["body"]
    need(ref.get("message")=="Not Found"
         and "ref" not in ref and "object" not in ref,
         "REF_NOT_FOUND_IDENTITY_UNTRUSTED")
    need(parent.proposed_request()=={"ref":REF,"sha":TARGET},
         "PARENT_CREATE_REF_SCOPE_MISMATCH")
    return {
        "shape_valid":True,
        "candidate_missing_in_supplied_receipts":True,
        "fixture_or_receipt_authenticity_verified":False,
        "live_origin_proven":False,
        "write_authorized":False,
        "real_cas_proven":False,
        "only_allowed_get_paths":[PATHS[k] for k in ORDER],
        "approved_workflow_sha":None
    }

def validate_readonly_transport_request(method,path):
    need(type(method) is str and method=="GET",
         "NON_GET_METHOD_NEVER_ALLOWED")
    need(type(path) is str and path in tuple(PATHS.values()),
         "UNSCOPED_GITHUB_GET_PATH_DENIED")
    return True

def future_readonly_get_once(method,path,*,token,transport_factory=None):
    """Existing disabled draft: fixed HTTPS GitHub GET only, never POST.

    This must NOT be called from active workflows or CI. No token is read
    from environment; caller must supply a separately reviewed short-lived
    GitHub token in a future, newly approved workflow.
    """
    need(LIVE_READONLY_NETWORK_GATE is True
         and type(EXTERNALLY_APPROVED_WORKFLOW_SHA) is str
         and HEX40.fullmatch(EXTERNALLY_APPROVED_WORKFLOW_SHA),
         "NO_NETWORK_PREFLIGHT_APPROVAL_IN_SOURCE")
    validate_readonly_transport_request(method,path)
    need(type(token) is str and len(token)>10
         and "\r" not in token and "\n" not in token,
         "SHORT_LIVED_EXPLICIT_TOKEN_REQUIRED")
    factory=HTTPSConnection if transport_factory is None else transport_factory
    conn=None
    try:
        conn=factory(GITHUB_HOST,timeout=10,context=ssl.create_default_context())
        conn.request("GET",path,headers={
            "Authorization":"Bearer "+token,
            "Accept":"application/vnd.github+json",
            "X-GitHub-Api-Version":"2022-11-28",
            "User-Agent":"task4-337-readonly-prewrite"
        })
        result=conn.getresponse()
        data=result.read(16385)
        need(len(data)<=16384,"UNBOUNDED_GITHUB_RESPONSE")
        parsed=json.loads(data.decode("utf-8"))
        need(type(parsed) is dict,"INVALID_GITHUB_JSON_OBJECT")
        return {"status":result.status,"body":parsed}
    except (HTTPException,OSError,TimeoutError,UnicodeError,ValueError) as exc:
        raise Denied("AMBIGUOUS_GITHUB_GET_NO_WRITE") from exc
    finally:
        if conn is not None:conn.close()

def real_create_ref_once(*args,**kwargs):
    raise Denied("TASK4_337_GITHUB_CREATE_REF_NOT_AUTHORIZED")

def review():
    contract=json.loads(CONTRACT.read_text(encoding="utf-8"))
    verify_contract(contract)
    staged.review()  # Checks all current Actions workflows stay read-only.
    need(parent.REAL_GITHUB_WRITE_SOURCE_GATE is False
         and parent.APPROVED_WORKFLOW_HEAD_SHA is None
         and parent.LIVE_PROVIDER_DISPATCH_ALLOWED is False,
         "PARENT_REAL_WRITER_SOURCE_GATE_MUST_STAY_OFF")
    need(LIVE_READONLY_NETWORK_GATE is False
         and REAL_GITHUB_WRITE_SOURCE_GATE is False
         and EXTERNALLY_APPROVED_WORKFLOW_SHA is None
         and PROVIDER_DISPATCH_ALLOWED is False,
         "THIS_SOURCE_MUST_NEVER_ENABLE_NETWORK_OR_WRITE")
    need(not ACTIVE_WRITER_WORKFLOW.exists(),"REAL_WRITER_WORKFLOW_NOT_PERMITTED")
    fixture=synthetic_get_fixture()
    verdict=verify_five_exact_gets(fixture,expected_head=REVIEW_MAIN)
    report={
        "rule_of_one":RULE,
        "classification":"FIVE_EXACT_SYNTHETIC_GETS_VALIDATE_SHAPE_ONLY",
        "manifest_sha256":sha(contract),
        "synthetic_get_fixture_sha256":sha(fixture),
        "synthetic_get_receipts_validated":5,
        "read_only_transport_source_gated_closed":True,
        "real_github_get_count":0,"real_github_post_count":0,
        "real_provider_post_count":0,
        "write_authorized":False,
        "live_cas_proven":False,
        "external_owner_write_consent_present":False,
        "future_live_recheck_required":True,
        "verdict":verdict,
        "provider_dispatch":"DENY"
    }
    report["report_sha256"]=sha(report)
    return report

def main(argv):
    need(len(argv)==2,"EXACT_ONE_OUTPUT_ARG")
    path=Path(argv[1]).resolve()
    need(path.parent==(ROOT/"results").resolve()
         and path.name=="task4-337-five-get-prewrite-offline-review.json"
         and not path.exists(),"ONLY_FRESH_FIXED_REPORT_PATH")
    r=review()
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print("TASK4_337_FIVE_GET_PREFLIGHT_SYNTHETIC_ONLY_ZERO_REAL_POSTS")

if __name__=="__main__": main(sys.argv)
