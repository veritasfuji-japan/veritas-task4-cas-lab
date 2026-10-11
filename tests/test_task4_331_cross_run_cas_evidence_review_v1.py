"""#331 offline synthetic separate GitHub-run evidence denial tests."""
from __future__ import annotations
from copy import deepcopy
import json
from pathlib import Path
import socket
import sys
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts import task4_331_cross_run_cas_receipt_arbiter_offline_v1 as m
from scripts import task4_330_github_create_ref_candidate_review_only_v1 as parent

def resign(x):
    for r in x["receipts"]:
        r["http_payload_sha256"]=m.sha(r["http_payload"])
        a=dict(r);a.pop("receipt_sha256",None)
        r["receipt_sha256"]=m.sha(a)
    return x

def test_four_distinct_synthetic_preflight_a_b_c_valid_but_not_real():
    b=m.synthetic_bundle()
    v=m.validate_bundle(b)
    assert v["classification"]==m.CLASSIFICATION
    assert v["distinct_synthetic_run_ids"]==v["distinct_synthetic_job_ids"]==4
    assert v["simulated_create_201"]==1
    assert v["simulated_duplicate_422"]==1
    assert v["simulated_separate_readback_200"]==1
    assert v["real_github_cross_run_cas_proven"] is False
    assert v["independent_real_github_api_evidence"] is False
    assert v["real_provider_dispatch_allowed"] is False
    assert v["real_github_ref_writes"]==v["provider_posts"]==0
    assert m.sha(b)==v["evidence_bundle_sha256"]

def test_which_runner_wins_is_not_assumed():
    b=m.synthetic_bundle()
    a=b["receipts"][1];other=b["receipts"][2]
    a["http_status"],other["http_status"]=other["http_status"],a["http_status"]
    a["http_payload"],other["http_payload"]=other["http_payload"],a["http_payload"]
    resign(b)
    assert m.validate_bundle(b)["real_github_cross_run_cas_proven"] is False

@pytest.mark.parametrize("index,field,value",[
 (1,"run_id","38139000001"),(2,"job_id","114490000002"),
 (3,"run_id","38139000003"),(0,"attempt",2),
 (1,"event","push"),(2,"workflow_ref","refs/heads/feature"),
 (3,"actor","attacker"),(1,"workflow_head_sha","a"*40),
 (2,"trial_ref","refs/heads/main"),(3,"target_commit","0"*40),
 (0,"repository","veritasfuji-japan/veritas_os"),
 (1,"origin","REAL_GITHUB"),(2,"origin","SYNTHETIC_EXTERNAL"),
 (0,"request_sha256","0"*64),(2,"http_status",409),
 (1,"http_status",422),(3,"http_status",404),(0,"http_status",200),
 (1,"http_payload",{"ref":"refs/heads/main","object":{"sha":m.FIXED_TARGET,"type":"commit"}}),
 (2,"http_payload",{"message":"Validation Failed"}),
 (3,"http_payload",{"ref":m.REF,"object":{"sha":"f"*40,"type":"commit"}}),
])
def test_mutated_independently_resigned_receipts_never_promote(index,field,value):
    b=deepcopy(m.synthetic_bundle())
    b["receipts"][index][field]=value
    resign(b)
    with pytest.raises(m.Denied):m.validate_bundle(b)

@pytest.mark.parametrize("field,value",[
 ("evidence_class","REAL_GITHUB"),("actual_github_ref_writes",1),
 ("actual_independent_github_actions_runs",4),
 ("actual_openai_posts",1),("provider_dispatch","ALLOW"),
 ("source_gate_still_closed",False),
 ("lab_repository","veritasfuji-japan/veritas_os"),
 ("exact_target_commit","0"*40),
 ("exact_candidate_ref","refs/heads/main"),
 ("planned_create_path","/repos/other/repo/git/refs"),
 ("planned_readback_path","/repos/other/repo/git/ref/heads/main"),
 ("rule_of_one","UNRESTRICTED"),
])
def test_forged_bundle_scope_and_liveness_denied(field,value):
    b=deepcopy(m.synthetic_bundle());b[field]=value
    with pytest.raises(m.Denied):m.validate_bundle(b)

@pytest.mark.parametrize("bad",[
 [],[{}],{},None,True,m.synthetic_bundle()["receipts"][:3],
 m.synthetic_bundle()["receipts"]+[{}]
])
def test_not_exact_four_receipts_denied(bad):
    b=deepcopy(m.synthetic_bundle());b["receipts"]=bad
    with pytest.raises(m.Denied):m.validate_bundle(b)

def test_lost_response_after_commit_is_not_claimed_duplicate():
    b=m.synthetic_bundle()
    b["receipts"][2]["http_status"]=None
    b["receipts"][2]["http_payload"]={"message":"timeout"}
    resign(b)
    with pytest.raises(m.Denied):m.validate_bundle(b)

def test_generic_github_422_validation_failure_denied_even_with_correct_status():
    b=m.synthetic_bundle()
    b["receipts"][2]["http_payload"]={
       "message":"Validation Failed",
       "errors":[{"code":"missing_field","field":"ref"}]
    }
    resign(b)
    with pytest.raises(m.Denied,match="422_ONLY_NOT_PROOF_OF_DUPLICATE"):
        m.validate_bundle(b)

def test_wrong_signature_denied():
    b=m.synthetic_bundle();b["receipts"][1]["receipt_sha256"]="0"*64
    with pytest.raises(m.Denied,match="RECEIPT_HASH_MISMATCH"):
        m.validate_bundle(b)
    b=m.synthetic_bundle();b["receipts"][1]["http_payload_sha256"]="0"*64
    b["receipts"][1]["receipt_sha256"]=m.sha(
        {k:v for k,v in b["receipts"][1].items() if k!="receipt_sha256"})
    with pytest.raises(m.Denied,match="HTTP_PAYLOAD_SHA_MISMATCH"):
        m.validate_bundle(b)

def test_added_unreviewed_claim_denied():
    b=m.synthetic_bundle();b["receipts"][1]["provider_allowed"]=True
    resign(b)
    with pytest.raises(m.Denied):m.validate_bundle(b)

def test_parent_github_source_gate_remains_off_even_under_fake_receipts():
    assert parent.REAL_GITHUB_WRITE_SOURCE_GATE is False
    assert parent.APPROVED_WORKFLOW_HEAD_SHA is None
    assert parent.LIVE_PROVIDER_DISPATCH_ALLOWED is False
    assert m.FIXED_TARGET==parent.TARGET_SHA
    assert m.REF==parent.EXPERIMENT_REF

def test_fixed_only_new_json_report_path(tmp_path,monkeypatch):
    monkeypatch.setattr(m,"ROOT",tmp_path)
    dst=tmp_path/"results"/"task4-331-offline-ab-c-receipt-report.json"
    r=m.emit_local_result(dst)
    assert r["report_sha256"]==json.loads(dst.read_text())["report_sha256"]
    without=dict(r);h=without.pop("report_sha256")
    assert m.sha(without)==h
    with pytest.raises(m.Denied):m.emit_local_result(dst)
    with pytest.raises(m.Denied):m.emit_local_result(tmp_path/"outside.json")

def test_no_network_possible_for_receipt_validator(monkeypatch):
    def fail(*a,**kw):pytest.fail("NO_NETWORK_PERMITTED_IN_OFFLINE_PROOF")
    monkeypatch.setattr(socket.socket,"connect",fail)
    monkeypatch.setattr(socket.socket,"connect_ex",fail)
    assert m.validate_bundle(m.synthetic_bundle())[
        "real_github_cross_run_cas_proven"] is False

def test_inert_future_run_book_not_an_activated_writer():
    workflow=(ROOT/".github/workflows/task4-331-offline-evidence-review-manual.yml").read_text()
    assert "workflow_dispatch:" in workflow
    assert "permissions:\n  contents: read" in workflow
    assert "persist-credentials: false" in workflow
    for k in ("pull_request:","pull_request_target:","push:",
              "contents: write","secrets.","github.token","gh api --method POST"):
        assert k not in workflow
    assert not (ROOT/".github/workflows/task4-331-real-ref-writer.yml").exists()
    doc=(ROOT/"docs/TASK4_331_CROSS_RUN_CAS_EVIDENCE_REVIEW_V1.md").read_text()
    assert "NOT AUTHORIZED" in doc
    assert "distinct GitHub-hosted Actions" in doc
    assert "contents:write" in doc

def test_contract_admits_synthetic_only_and_provider_deny():
    c=json.loads((ROOT/"contracts/TASK4_331_SYNTHETIC_CROSS_RUN_EVIDENCE_V1.json").read_text())
    assert c["rule_of_one"]==m.RULE
    assert c["candidate_ref"]==m.REF
    assert c["target_sha"]==m.FIXED_TARGET
    assert c["existing_lab_main_baseline"]==m.FIXTURE_WORKFLOW_HEAD
    assert c["expected_synthetic_run_count"]==4
    assert c["actual_github_ref_create_requests"]==0
    assert c["actual_distinct_github_hosted_runs_tested"]==0
    assert c["real_github_cross_run_cas_proven"] is False
    assert c["real_github_ref_immutable_proven"] is False
    assert c["no_ref_writes_authorized"] is True
    assert c["separate_new_owner_approval_required"] is True
    assert c["provider_dispatch"]=="DENY"
