"""Task4 #333: defend read-only point-in-time evidence against authority promotion."""
from copy import deepcopy
import json
from pathlib import Path
import socket
import sys
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts import task4_333_github_readonly_prestate_review_only_v1 as m

def record():
    return json.loads(m.CONTRACT.read_text())

def test_baseline_is_not_runtime_authorization():
    d=record()
    assert m.verify(d)
    r=m.review()
    assert r["git_ref_write_authorized"] is False
    assert r["real_cas_proven"] is False
    assert r["github_ref_immutability_attested"] is False
    assert r["private_actions_budget_verified"] is False
    assert r["preflight_must_be_repeated_at_runtime"] is True
    assert r["real_github_post_count"]==r["real_provider_post_count"]==0
    h=r.pop("report_sha256")
    assert m.digest(r)==h

@pytest.mark.parametrize("key,value",[
 ("lab_visibility","public"),("source_main_commit_sha","0"*40),
 ("target_existing_git_commit_sha","0"*40),
 ("candidate_ref","refs/heads/main"),("target_commit_get_result","UNVERIFIED"),
 ("candidate_ref_get_http_status",200),("candidate_ref_get_message","OK"),
 ("candidate_namespace_matching_ref_count",1),
 ("github_rulesets_get_http_status",200),
 ("github_branch_protection_get_http_status",200),
 ("github_ruleset_enforcement_proven",True),
 ("branch_protection_enforcement_proven",True),
 ("admin_ref_immutability_proven",True),
 ("private_actions_remaining_minutes",2000),
 ("private_actions_spending_cap_verified",True),
 ("predecessor_332_run_id","38139656086"),
 ("predecessor_332_zip_sha256","a"*64),
 ("actual_write_attempt_count_in_333",1),
 ("actual_provider_post_count_in_333",1),
 ("future_writer_workflow_authorized",True),
 ("fresh_owner_ref_write_consent_present",True),
 ("real_cross_run_cas_proven",True),
 ("nonresettable_consume_once_authority_proven",True),
 ("classification","PROVEN"),("provider_dispatch","ALLOW")
])
def test_any_source_or_authority_drift_denied(key,value):
    d=deepcopy(record());d[key]=value
    with pytest.raises(m.Denied):m.verify(d)

def test_extra_missing_and_malformed_denied():
    for value in (None,[],False,"text"):
        with pytest.raises(m.Denied):m.verify(value)
    a=record();a["other_claim"]=True
    with pytest.raises(m.Denied):m.verify(a)
    b=record();del b["provider_dispatch"]
    with pytest.raises(m.Denied):m.verify(b)

def test_existing_writers_remain_disabled_without_new_workflows():
    assert m.verify_gates()

def test_no_network_or_real_api_access(monkeypatch):
    def forbidden(*args,**kwargs):pytest.fail("NO_NETWORK_PERMITTED")
    monkeypatch.setattr(socket.socket,"connect",forbidden)
    monkeypatch.setattr(socket.socket,"connect_ex",forbidden)
    assert m.review()["provider_dispatch"]=="DENY"

def test_no_output_elsewhere(tmp_path,monkeypatch):
    monkeypatch.setattr(m,"ROOT",tmp_path)
    with pytest.raises(m.Denied):m.main(["program",str(tmp_path/"arbitrary.json")])
