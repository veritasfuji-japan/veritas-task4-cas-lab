#!/usr/bin/env python3
"""#338: exact five authenticated GitHub GETs; no POST/PUT/PATCH/DELETE.

Only the separately manual-dispatched read-only GitHub Actions job calls this
file with github.token (contents:read). Never logs or saves token or full
GitHub response JSON. An omitted bypass_actors field is UNKNOWN, not [].
A clean observation is NOT writer authority; future A/B MUST recheck.
"""
from __future__ import annotations
import hashlib
from http.client import HTTPSConnection, HTTPException
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from scripts import task4_337_live_get_prewrite_boundary_review_only_v1 as parent
from scripts import task4_335_ruleset_prewrite_candidate_review_only_v1 as rules
from scripts import task4_330_github_create_ref_candidate_review_only_v1 as source

RULE="TASK4_338_REAL_AUTHENTICATED_GITHUB_GET_NO_EXECUTION_AUTHORITY"
REPO=parent.REPO
REPO_ID=1414228001
REF=parent.REF
TARGET=parent.TARGET
RULESET_ID=24880024
RULESET_UPDATED_AT="2026-10-11T22:00:45.379+09:00"
WORKFLOW="task4-338-live-authenticated-readonly-preflight-manual.yml"
HOST="api.github.com"
LIMIT_BYTES=262144
KEYS=tuple(parent.ORDER)
HEX40=re.compile(r"[0-9a-f]{40}\Z")
CONTRACT=ROOT/"contracts/TASK4_338_LIVE_AUTHENTICATED_READONLY_PREFLIGHT_V1.json"
PROVIDER_KEYS=("OPENAI_API_KEY","TASK4_OPENAI_API_KEY","ANTHROPIC_API_KEY","OPENAI_BASE_URL","VERITAS_DATABASE_URL")

class Denied(ValueError):pass

def need(value,reason):
    if not value:raise Denied(reason)

def canonical(obj):
    return json.dumps(obj,sort_keys=True,ensure_ascii=False,
                      separators=(",",":"),allow_nan=False).encode("utf-8")

def digest(obj):return hashlib.sha256(canonical(obj)).hexdigest()

def expected_contract():
    return {
        "schema":"veritas.task4.live-authenticated-five-get-readonly-preflight.v1",
        "rule_of_one":RULE,"repo":REPO,"repo_id":REPO_ID,
        "visibility":"public",
        "workflow_path":".github/workflows/"+WORKFLOW,
        "trial_ref":REF,"target_sha":TARGET,"ruleset_id":RULESET_ID,
        "ruleset_updated_at":RULESET_UPDATED_AT,
        "ruleset_rules":["deletion","non_fast_forward","update"],
        "read_only_token_permissions":"contents:read",
        "auth_token_source":"github.token only in manual readonly workflow",
        "get_endpoints":list(KEYS),
        "expected_status":[200,200,200,200,404],
        "source_main_at_review":"bdf7d0edd37a204a875d9238fd01a1b142610685",
        "allowed_methods":["GET"],"max_requests":5,"max_retries":0,
        "allow_bypass_field_withheld_as_proof":False,
        "actor_bypass_visibility_required_for_full_success":True,
        "workflow_dispatch_only":True,"manual_owner_actor_only":True,
        "main_branch_only":True,"run_attempt":"1",
        "github_write_post_authorized":False,"actual_git_ref_write_count":0,
        "provider_posts":0,"real_cas_proven":False,
        "admin_irrevocability_proven":False,
        "classification":"LIVE_READONLY_GET_EVIDENCE_ONLY_NOT_A_POST_AUTHORIZATION"
    }

def verify_contract(d):
    want=expected_contract()
    need(type(d) is dict and set(d)==set(want),"CONTRACT_FIELDS_NOT_EXACT")
    for k,v in want.items():
        need(type(d[k]) is type(v) and d[k]==v,"CONTRACT_DRIFT_"+k)
    need(source.REAL_GITHUB_WRITE_SOURCE_GATE is False
         and source.APPROVED_WORKFLOW_HEAD_SHA is None
         and source.LIVE_PROVIDER_DISPATCH_ALLOWED is False,
         "WRITER_OR_PROVIDER_SOURCE_GATE_CHANGED")
    return True

def verify_context(env,*,checkout_sha):
    need(type(env) is dict,"ACTION_CONTEXT_DICT_REQUIRED")
    required={
        "GITHUB_REPOSITORY":REPO,
        "GITHUB_REPOSITORY_ID":str(REPO_ID),
        "GITHUB_REF":"refs/heads/main",
        "GITHUB_EVENT_NAME":"workflow_dispatch",
        "GITHUB_RUN_ATTEMPT":"1",
        "GITHUB_ACTOR":"veritasfuji-japan",
        "GITHUB_WORKFLOW_REF":REPO+"/.github/workflows/"+WORKFLOW+"@refs/heads/main"
    }
    for key,val in required.items():
        need(env.get(key)==val,"INVALID_ACTION_CONTEXT_"+key)
    head=env.get("GITHUB_SHA")
    need(type(head) is str and HEX40.fullmatch(head)
         and checkout_sha==head,"ACTION_HEAD_CHECKOUT_MISMATCH")
    need(type(env.get("GITHUB_RUN_ID")) is str
         and re.fullmatch(r"[1-9][0-9]{7,15}",env["GITHUB_RUN_ID"]),
         "ACTIONS_RUN_ID_INVALID")
    for key in PROVIDER_KEYS:
        need(not env.get(key),"ANY_PROVIDER_CREDENTIAL_OR_ENDPOINT_DENIED")
    token=env.get("GH_TOKEN")
    need(type(token) is str and len(token)>15
         and "\r" not in token and "\n" not in token,
         "EPHEMERAL_GITHUB_READ_TOKEN_REQUIRED")
    return head

def exact_get_one(key,*,token,transport_factory=None):
    need(key in KEYS,"UNSCOPED_GET_KEY")
    path=parent.PATHS[key]
    parent.validate_readonly_transport_request("GET",path)
    factory=HTTPSConnection if transport_factory is None else transport_factory
    conn=None
    try:
        conn=factory(HOST,timeout=12,context=ssl.create_default_context())
        # No redirects, no client retries, no user-configurable method or URL.
        conn.request("GET",path,headers={
            "Authorization":"Bearer "+token,
            "Accept":"application/vnd.github+json",
            "X-GitHub-Api-Version":"2022-11-28",
            "User-Agent":"veritas-task4-338-readonly-five-get"
        })
        response=conn.getresponse()
        raw=response.read(LIMIT_BYTES+1)
        need(len(raw)<=LIMIT_BYTES,"GITHUB_GET_OVERSIZED")
        body=json.loads(raw.decode("utf-8"))
        need(type(body) is dict,"GITHUB_GET_INVALID_JSON")
        return {"status":response.status,"body":body}
    except (HTTPException,OSError,TimeoutError,UnicodeError,ValueError) as exc:
        raise Denied("GITHUB_GET_FAILED_CLOSED_"+key) from exc
    finally:
        if conn is not None:conn.close()

def static_ruleset_drift_fields(body):
    """Only allowlisted FIELD NAMES and presence labels, never response values.

    Missing fields and changed security-critical fields both fail closed.
    Deliberately do not treat missing bypass actors as a verified empty list.
    """
    expected={
        "id":RULESET_ID,
        "enforcement":"active",
        "name":"task4-cas-proof-ref-protection",
        "target":"branch",
        "source_type":"Repository",
        "updated_at":RULESET_UPDATED_AT,
        "conditions":rules.expected_ruleset()["conditions"],
        "rules":rules.expected_ruleset()["rules"]
    }
    if type(body) is not dict:
        return ["ruleset:invalid"]
    return [
        name+(":missing" if name not in body else ":mismatch")
        for name,want in expected.items()
        if name not in body or
           type(body[name]) is not type(want) or body[name]!=want
    ]


def evaluate(responses,*,expected_sha):
    need(type(responses) is dict and set(responses)==set(KEYS),
         "FIVE_EXACT_GET_RECEIPTS_REQUIRED")
    for key in KEYS:
        x=responses[key]
        need(type(x) is dict and set(x)=={"status","body"}
             and type(x["status"]) is int
             and x["status"]==parent.STATUSES[key]
             and type(x["body"]) is dict,
             "UNEXPECTED_GET_RESPONSE_"+key)
    repo=responses["repository"]["body"]
    need(type(repo.get("id")) is int and repo["id"]==REPO_ID
         and repo.get("full_name")==REPO
         and repo.get("visibility")=="public"
         and repo.get("private") is False
         and repo.get("default_branch")=="main","REPOSITORY_IDENTITY_INVALID")
    need(type(expected_sha) is str and HEX40.fullmatch(expected_sha)
         and responses["main"]["body"].get("sha")==expected_sha,
         "MAIN_HEAD_NOT_RUN_PINNED")
    need(responses["target"]["body"].get("sha")==TARGET,
         "FROZEN_TARGET_COMMIT_INVALID")
    ruleset=responses["ruleset"]["body"]
    need(not static_ruleset_drift_fields(ruleset),
         "RULESET_STATIC_RULES_DRIFT")
    need(responses["candidate"]["body"].get("message")=="Not Found"
         and "ref" not in responses["candidate"]["body"]
         and "object" not in responses["candidate"]["body"],
         "MISSING_REF_AMBIGUOUS")
    # Metadata-read Github tokens may legally omit bypass_actors, never coerce.
    bypass_visible="bypass_actors" in ruleset
    bypass=ruleset.get("bypass_actors")
    if bypass_visible:
        need(type(bypass) is list and bypass==[],
             "RULESET_BYPASS_NOT_EMPTY")
    actor_visible="current_user_can_bypass" in ruleset
    if actor_visible:
        need(ruleset["current_user_can_bypass"]=="never",
             "CURRENT_ACTOR_CAN_BYPASS")
    fully_visible=bypass_visible and actor_visible
    return {
        "classification":("FIVE_LIVE_GET_SHAPES_COMPLETE_NOT_AUTHORITY" if fully_visible
                          else "FIVE_LIVE_GETS_BYPASS_VISIBILITY_INCOMPLETE"),
        "all_five_expected_http_statuses":True,
        "observed_ref_missing_at_this_instant":True,
        "ruleset_bypass_list_visible":bypass_visible,
        "current_actor_bypass_visible":actor_visible,
        "ruleset_full_bypass_verified":fully_visible,
        "admin_can_modify_ruleset_not_excluded":True,
        "write_authorized":False,"real_cross_run_cas_proven":False
    }

def build_report(responses,*,head,env):
    verdict=evaluate(responses,expected_sha=head)
    return {
        "rule_of_one":RULE,
        "run_id":env["GITHUB_RUN_ID"],
        "workflow_ref":env["GITHUB_WORKFLOW_REF"],
        "event":env["GITHUB_EVENT_NAME"],
        "head_sha":head,
        "source":"AUTHENTICATED_GITHUB_HOSTED_ACTIONS_GET",
        "exact_get_paths":[parent.PATHS[k] for k in KEYS],
        "http_statuses":{k:responses[k]["status"] for k in KEYS},
        "body_sha256":{k:digest(responses[k]["body"]) for k in KEYS},
        "verdict":verdict,
        "actual_authenticated_get_count":5,
        "real_github_create_ref_post_count":0,
        "real_provider_post_count":0,
        "approval_token_persisted":False,
        "read_response_body_persisted":False,
        "github_write_permission_granted":False,
        "future_writer_authorized":False,
        "provider_dispatch":"DENY"
    }

def failclosed_evidence(responses,*,head,env,reason):
    """Produce a useful negative receipt with NO response body or token."""
    allowed={
        "FIVE_EXACT_GET_RECEIPTS_REQUIRED",
        "REPOSITORY_IDENTITY_INVALID",
        "MAIN_HEAD_NOT_RUN_PINNED",
        "FROZEN_TARGET_COMMIT_INVALID",
        "RULESET_STATIC_RULES_DRIFT",
        "MISSING_REF_AMBIGUOUS",
        "RULESET_BYPASS_NOT_EMPTY",
        "CURRENT_ACTOR_CAN_BYPASS",
        "GITHUB_GET_OVERSIZED",
        "GITHUB_GET_INVALID_JSON",
        "UNSCOPED_GET_KEY"
    }
    allowed.update("UNEXPECTED_GET_RESPONSE_"+k for k in KEYS)
    allowed.update("GITHUB_GET_FAILED_CLOSED_"+k for k in KEYS)
    code=reason if reason in allowed else "UNKNOWN_PREWRITE_DENIAL"
    static_drift=(static_ruleset_drift_fields(
        responses["ruleset"]["body"])
        if code=="RULESET_STATIC_RULES_DRIFT"
           and "ruleset" in responses else [])
    return {
        "rule_of_one":RULE,
        "run_id":env["GITHUB_RUN_ID"],
        "workflow_ref":env["GITHUB_WORKFLOW_REF"],
        "head_sha":head,
        "classification":"AUTHENTICATED_READONLY_PREFLIGHT_FAIL_CLOSED",
        "verification_outcome":"FAIL_CLOSED",
        "failure_code":code,
        "ruleset_static_drift_fields":static_drift,
        "source":"AUTHENTICATED_GITHUB_HOSTED_ACTIONS_GET",
        "exact_get_paths":[parent.PATHS[k] for k in KEYS],
        "http_statuses":{k:responses[k]["status"] for k in responses},
        "body_sha256":{k:digest(responses[k]["body"]) for k in responses},
        "actual_authenticated_get_count":len(responses),
        "real_github_create_ref_post_count":0,
        "real_provider_post_count":0,
        "approval_token_persisted":False,
        "read_response_body_persisted":False,
        "github_write_permission_granted":False,
        "future_writer_authorized":False,
        "provider_dispatch":"DENY"
    }


def run(env,*,checkout_sha,transport_factory=None):
    contract=json.loads(CONTRACT.read_text(encoding="utf-8"))
    verify_contract(contract)
    head=verify_context(env,checkout_sha=checkout_sha)
    responses={}
    # Hard finite five-item GET sequence; absolutely NO retry or POST.
    try:
        for key in KEYS:
            responses[key]=exact_get_one(key,token=env["GH_TOKEN"],
                                         transport_factory=transport_factory)
        report=build_report(responses,head=head,env=env)
        report["verification_outcome"]="PASS_READONLY_ONLY"
        report["failure_code"]=None
        report["ruleset_static_drift_fields"]=[]
    except Denied as exc:
        report=failclosed_evidence(responses,head=head,env=env,reason=str(exc))
    report["report_sha256"]=digest(report)
    return report

def main(argv):
    need(len(argv)==2,"EXACT_FIXED_RESULT_ARG_REQUIRED")
    dest=Path(argv[1]).resolve()
    need(dest.parent==(ROOT/"results").resolve()
         and dest.name=="task4-338-live-readonly-preflight.json"
         and not dest.exists(),"REPORT_DESTINATION_NOT_NEW_OR_FIXED")
    head=subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip()
    r=run(dict(os.environ),checkout_sha=head)
    dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(r,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    if r["verification_outcome"]=="FAIL_CLOSED":
        print("TASK4_339_READONLY_PREFLIGHT_FAIL_CLOSED")
        print("TASK4_339_SAFE_FAILURE_CODE="+r["failure_code"])
        raise SystemExit(1)
    print("TASK4_338_AUTHENTICATED_FIVE_REAL_GITHUB_GETS_COMPLETED_NO_WRITE")
    print("TASK4_338_CLASSIFICATION="+r["verdict"]["classification"])

if __name__=="__main__": main(sys.argv)
