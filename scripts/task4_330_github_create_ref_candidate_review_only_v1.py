#!/usr/bin/env python3
"""Task4 #330 review-only exact GitHub CreateRef candidate: NO executable live writer.

Important:
 * Every real GitHub POST path is HARD SOURCE-GATED CLOSED in this PR.
 * No Actions workflow here has contents:write; no API token is read by the
   review-only CLI. The only executable mode produces offline synthetic proof.
 * Later live experiments need a SEPARATE authorized PR and a fresh workflow
   SHA pin, and cannot be enabled by an environment variable alone.
 * An HTTP 422 is NEVER equivalent to a proven duplicate without independent
   real GET/ref identity evidence. Unknown means no retry and no authority.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
from http.client import HTTPSConnection, HTTPException
import json
import ssl
import os
from pathlib import Path
import re
import sys

RULE="TASK4_330_GITHUB_REAL_CREATE_REF_SOURCE_GATED_CLOSED_V1"
LAB="veritasfuji-japan/veritas-task4-cas-lab"
SOURCE="veritasfuji-japan/rcc-revas-veritas-benchmark"
MERGED_LAB_MAIN="9edd28eee24da559fc0ad24fd97291944acc2ed4"
SOURCE_MAIN="e3365d35054c06df09a37f3f4926bbe6c2fdba06"
PINNED_329_SCOPE="de45893cb289d9bca20ab879ac6d2f73a09d8f36dfc9646895b6076f41209728"
EXPERIMENT_REF="refs/heads/offline-test-ledger/task4-329-"+PINNED_329_SCOPE[:32]
# Creation will point to an immutable, already-existing *initial lab* commit.
# This never advances main. Exact ref is not a production lease.
TARGET_SHA=MERGED_LAB_MAIN
POST_PATH="/repos/"+LAB+"/git/refs"
GET_PATH="/repos/"+LAB+"/git/ref/"+EXPERIMENT_REF.removeprefix("refs/")
GITHUB_HOST="api.github.com"
GITHUB_API_VERSION="2022-11-28"
HEX40=re.compile(r"[0-9a-f]{40}\Z")
# These MUST remain unconditionally locked in this PR.
REAL_GITHUB_WRITE_SOURCE_GATE=False
APPROVED_WORKFLOW_HEAD_SHA=None
LIVE_PROVIDER_DISPATCH_ALLOWED=False
PROVIDER_KEYS=("OPENAI_API_KEY","TASK4_OPENAI_API_KEY","ANTHROPIC_API_KEY",
               "OPENAI_BASE_URL","VERITAS_DATABASE_URL")
ROOT=Path(__file__).resolve().parents[1]

class Denied(ValueError): pass

def need(ok,reason):
    if not ok: raise Denied(reason)

def canonical(v):
    return json.dumps(v,sort_keys=True,ensure_ascii=False,
                      separators=(",",":"),allow_nan=False).encode("utf-8")

def digest(v):
    return hashlib.sha256(canonical(v)).hexdigest()

def proposed_request():
    need(HEX40.fullmatch(TARGET_SHA) is not None,
         "INVALID_PINNED_EXISTING_LAB_COMMIT")
    need(EXPERIMENT_REF.startswith("refs/heads/offline-test-ledger/task4-329-")
         and EXPERIMENT_REF.endswith(PINNED_329_SCOPE[:32]),
         "TRIAL_REF_OUT_OF_ISOLATED_LAB_SCOPE")
    return {"ref":EXPERIMENT_REF,"sha":TARGET_SHA}

def classify_create_ref_response(code,body):
    """Classify fake HTTP receipts conservatively. Never infer authority."""
    request=proposed_request()
    if type(code) is not int or type(body) is not dict:
        result="UNKNOWN_INVALID_RESPONSE"
    elif code==201:
        ref=body.get("ref")
        obj=body.get("object")
        if ref==request["ref"] and type(obj) is dict and obj.get("sha")==request["sha"]:
            result="CANDIDATE_CREATED_REQUIRES_INDEPENDENT_REAL_GET"
        else:
            result="UNKNOWN_201_WRONG_REF_OR_TARGET"
    elif code==422:
        result="VALIDATION_OR_ALREADY_EXISTS_UNPROVEN"
    elif code==409:
        result="UNKNOWN_CONFLICT_NO_RETRY"
    elif code in (401,403):
        result="DENIED_TOKEN_OR_PERMISSION"
    elif code==404:
        result="UNKNOWN_404_NO_RETRY"
    else:
        result="UNKNOWN_SERVER_OR_NETWORK_NO_RETRY"
    return {
      "rule_of_one":RULE,"requested_ref":EXPERIMENT_REF,
      "classification":result,"real_github_evidence":False,
      "real_github_create_ref_authorized":False,
      "live_provider_dispatch":False,"automated_post_retry_permitted":False,
      "independent_real_get_required":True
    }

def fake_scenarios():
    return {
       "mock_created":(201,{"ref":EXPERIMENT_REF,
                            "object":{"sha":TARGET_SHA,"type":"commit"}}),
       "mock_created_wrong_ref":(201,{"ref":"refs/heads/main",
                                     "object":{"sha":TARGET_SHA}}),
       "mock_created_wrong_sha":(201,{"ref":EXPERIMENT_REF,
                                     "object":{"sha":"0"*40}}),
       "mock_validation_error":(422,{"message":"Validation Failed",
                                     "errors":[{"code":"missing_field"}]}),
       "mock_existing_ref_error":(422,{"message":"Reference already exists"}),
       "mock_conflict":(409,{"message":"Conflict"}),
       "mock_auth_denied":(403,{"message":"Resource not accessible"}),
       "mock_server_error":(500,{"message":"Internal Server Error"}),
       "mock_timeout":(None,None)
    }

def offline_review_report():
    need(REAL_GITHUB_WRITE_SOURCE_GATE is False
         and APPROVED_WORKFLOW_HEAD_SHA is None
         and LIVE_PROVIDER_DISPATCH_ALLOWED is False,
         "SOURCE_MUST_NEVER_ENABLE_ANY_REAL_WRITE_OR_PROVIDER")
    assert proposed_request()=={"ref":EXPERIMENT_REF,"sha":MERGED_LAB_MAIN}
    events={}
    for name,(code,body) in fake_scenarios().items():
        res=classify_create_ref_response(code,body)
        events[name]={
          "synthetic":True,"fake_http_status":code,
          "classification":res["classification"],
          "request_sha256":digest(proposed_request()),
          "real_github_evidence":False,
          "provider_dispatch":False
        }
    report={
      "rule_of_one":RULE,"repository":LAB,
      "source_repository":SOURCE,
      "source_merged_main_sha":SOURCE_MAIN,
      "lab_prior_main_sha":MERGED_LAB_MAIN,
      "proposed_only_ref":EXPERIMENT_REF,
      "proposed_only_ref_target":TARGET_SHA,
      "would_be_git_create_ref_path":POST_PATH,
      "would_be_readback_path":GET_PATH,
      "source_gate_open":False,
      "new_approved_workflow_sha":None,
      "real_github_ref_create_calls":0,
      "actual_independent_actions_run_ids":[],
      "real_github_ref_cas_confirmed":False,
      "remote_ref_immutable_or_admin_protected_proven":False,
      "available_source_workflow_contents_write":False,
      "workflow_dispatch_writer_enabled":False,
      "actual_api_token_read":False,
      "actual_github_network_calls":0,
      "real_provider_posts":0,
      "new_real_model_scores":0,
      "actual_bank_effects":0,
      "live_provider_dispatch":"DENY",
      "scenarios":events,
      "classification":"OFFLINE_REVIEW_ONLY_FUTURE_GITHUB_CAS_NOT_EXECUTED"
    }
    report["report_sha256"]=digest(report)
    return report

def real_create_ref_once_under_future_authorization(*,env=None,transport_factory=None):
    """Intentionally UNREACHABLE on the shipped revision.

    Future separate consent-reviewed PR must explicitly flip the hard source
    gate, freeze exact approved main workflow SHA, add scoped token handling
    and a protected manual workflow. Keeping this function disabled means
    nothing here can send a GitHub POST, regardless of caller/env.
    """
    need(REAL_GITHUB_WRITE_SOURCE_GATE is True and
         type(APPROVED_WORKFLOW_HEAD_SHA) is str and
         HEX40.fullmatch(APPROVED_WORKFLOW_HEAD_SHA) is not None,
         "FUTURE_REAL_GITHUB_REF_WRITE_NOT_APPROVED_IN_SOURCE")
    values=os.environ if env is None else env
    need(type(values) is dict or values is os.environ,
         "EXACT_FUTURE_WORKFLOW_CONTEXT_REQUIRED")
    need(values.get("GITHUB_REPOSITORY")==LAB
         and values.get("GITHUB_REF")=="refs/heads/main"
         and values.get("GITHUB_EVENT_NAME")=="workflow_dispatch"
         and values.get("GITHUB_RUN_ATTEMPT")=="1"
         and str(values.get("GITHUB_RUN_ID","")).isdigit()
         and values.get("GITHUB_SHA")==APPROVED_WORKFLOW_HEAD_SHA,
         "FUTURE_GITHUB_MAIN_MANUAL_ONE_ATTEMPT_AND_EXACT_HEAD_REQUIRED")
    workflow=(LAB+"/.github/workflows/"
              "task4-330-authorized-create-ref.yml@refs/heads/main")
    need(values.get("GITHUB_WORKFLOW_REF")==workflow,
         "FUTURE_REVIEWED_DEFAULT_BRANCH_WORKFLOW_REQUIRED")
    need(not any(values.get(k) for k in PROVIDER_KEYS),
         "ANY_PROVIDER_SECRET_OR_ENDPOINT_DENIED")
    token=values.get("GITHUB_TOKEN")
    need(type(token) is str and len(token)>10 and "\\n" not in token
         and "\\r" not in token,"ONLY_SHORT_LIVED_JOB_GITHUB_TOKEN_ALLOWED")
    headers={
       "Authorization":"Bearer "+token,
       "Accept":"application/vnd.github+json",
       "Content-Type":"application/json",
       "X-GitHub-Api-Version":GITHUB_API_VERSION,
       "User-Agent":"task4-330-isolated-lab-one-shot"
    }
    # Caller may inject a controlled fake HTTPSConnection factory in unit tests.
    # In production this reaches ONLY the fixed api.github.com hostname.
    factory=HTTPSConnection if transport_factory is None else transport_factory
    conn=None
    status=None
    payload=None
    try:
        conn=factory(GITHUB_HOST,timeout=10,context=ssl.create_default_context())
        # EXACTLY ONE POST. There is deliberately no retry loop, follow-redirect
        # logic, external endpoint, arbitrary user-specified ref, or force mode.
        conn.request("POST",POST_PATH,body=canonical(proposed_request()),
                     headers=headers)
        response=conn.getresponse()
        status=response.status
        b=response.read(4097)
        if len(b)<=4096:
            payload=json.loads(b.decode("utf-8"))
    except (HTTPException,OSError,TimeoutError,UnicodeError,ValueError):
        status=None
        payload=None
    finally:
        if conn is not None:conn.close()
    outcome=classify_create_ref_response(status,payload)
    outcome["real_github_evidence"]=False  # Must be reconciled by a third run.
    outcome["real_github_create_ref_authorized"]=False # Not Provider authority.
    return outcome

def write_report(output):
    target=Path(output).resolve()
    need(target.parent==(ROOT/"results").resolve() and
         target.name=="task4-330-review-only-report.json"
         and not target.exists(),
         "ONLY_NEW_FIXED_LOCAL_REPORT_PATH")
    target.parent.mkdir(parents=True,exist_ok=True)
    r=offline_review_report()
    target.write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    return r

def main():
    need(len(sys.argv)==2,"USAGE: script.py results/task4-330-review-only-report.json")
    result=write_report(sys.argv[1])
    need(result["real_github_ref_create_calls"]==0 and
         result["live_provider_dispatch"]=="DENY",
         "MUST_REMAIN_NO_WRITE")
    print("TASK4_330_SOURCE_GATED_GITHUB_CAS_REVIEW_ONLY_ZERO_REAL_POSTS")

if __name__=="__main__":
    main()
