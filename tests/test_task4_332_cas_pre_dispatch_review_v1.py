"""#332: authorization-preflight refusal tests, strictly offline."""
from copy import deepcopy
from pathlib import Path
import json
import socket
import sys
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts import task4_332_cas_pre_dispatch_authorization_review_only_v1 as m

def base():
    return json.loads(m.CONTRACT.read_text())

def test_frozen_review_passes_without_promoting_real_authority():
    m.verify_manifest(base())
    result=m.review()
    assert result["classification"]=="OFFLINE_REVIEW_VALID_BUT_NOT_AUTHORIZED"
    assert result["actual_git_ref_create_post_count"]==0
    assert result["actual_provider_post_count"]==0
    assert result["real_github_write_authorized"] is False
    assert result["provider_dispatch"]=="DENY"
    assert result["report_sha256"]==m.digest({k:v for k,v in result.items()
                                              if k!="report_sha256"})

@pytest.mark.parametrize("key,value",[
    ("source_reviewed_main_sha","0"*40),
    ("predecessor_artifact_zip_sha256","0"*64),
    ("ref","refs/heads/main"),
    ("target_commit","f"*40),
    ("create_path","/repos/other/repo/git/refs"),
    ("readback_path","/repos/other/repo/git/ref/heads/main"),
    ("planned_roles",["A","B","C"]),
    ("planned_roles",["PREFLIGHT","A","A","C"]),
    ("proposed_max_post_attempts",3),
    ("proposed_max_post_attempts_per_writer",2),
    ("proposed_automatic_retries",1),
    ("proposed_total_runner_minutes",64),
    ("approved_frozen_writer_workflow_head_sha","a"*40),
    ("signed_owner_write_approval_ref","self-signed"),
    ("validated_private_actions_budget_minutes",32),
    ("verified_ref_absent",True),
    ("verified_fixed_target_exists",True),
    ("independent_admin_custody_attested",True),
    ("source_gate_enabled",True),
    ("active_write_workflow",True),
    ("actual_git_ref_create_post_count",1),
    ("actual_provider_post_count",1),
    ("real_cross_run_cas_proven",True),
    ("real_single_use_irrevocable_proven",True),
    ("provider_dispatch","ALLOW"),
    ("state","AUTHORIZED"),
])
def test_unreviewed_or_unsafe_claim_denied(key,value):
    data=deepcopy(base());data[key]=value
    with pytest.raises(m.Denied):m.verify_manifest(data)

@pytest.mark.parametrize("value",[[],None,"",True])
def test_manifest_shape_denied(value):
    with pytest.raises(m.Denied):m.verify_manifest(value)

def test_added_or_missing_fields_denied():
    data=base();data["approval_implied"]=True
    with pytest.raises(m.Denied):m.verify_manifest(data)
    data=base();del data["actual_provider_post_count"]
    with pytest.raises(m.Denied):m.verify_manifest(data)

def test_parent_source_hard_gates_closed_and_no_writer_workflows():
    names=m.verify_source_gates()
    assert len(names)==4
    assert "task4-332-manual-preauthorization-review-only.yml" in names

def test_no_network_from_review_logic(monkeypatch):
    def blocked(*args,**kwargs):pytest.fail("NETWORK_IS_FORBIDDEN")
    monkeypatch.setattr(socket.socket,"connect",blocked)
    monkeypatch.setattr(socket.socket,"connect_ex",blocked)
    assert m.review()["real_github_write_authorized"] is False

def test_exact_new_report_path_only(tmp_path,monkeypatch):
    monkeypatch.setattr(m,"ROOT",tmp_path)
    with pytest.raises(Exception):
        m.main(["prog",str(tmp_path/"unsafe.json")])
