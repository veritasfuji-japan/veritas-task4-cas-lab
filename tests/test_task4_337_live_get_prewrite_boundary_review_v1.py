"""Task4 #337: strict five-GET prewrite shape and source-gated refusal tests."""
from copy import deepcopy
import json
from pathlib import Path
import socket
import sys
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts import task4_337_live_get_prewrite_boundary_review_only_v1 as m

def fixture():return m.synthetic_get_fixture()
def verify(x,sha=None):
    return m.verify_five_exact_gets(x,expected_head=m.REVIEW_MAIN if sha is None else sha)

def test_five_gets_accepted_as_synthetic_shape_only():
    verdict=verify(fixture())
    assert verdict["shape_valid"] is True
    assert verdict["write_authorized"] is False
    assert verdict["live_origin_proven"] is False
    assert verdict["real_cas_proven"] is False
    assert verdict["approved_workflow_sha"] is None
    assert verdict["only_allowed_get_paths"]==[m.PATHS[x] for x in m.ORDER]

@pytest.mark.parametrize("key",list(m.ORDER))
def test_required_get_missing_denied(key):
    data=fixture();del data[key]
    with pytest.raises(m.Denied):verify(data)

@pytest.mark.parametrize("key",list(m.ORDER))
def test_get_unexpected_status_denied(key):
    data=fixture();data[key]["status"]=403
    with pytest.raises(m.Denied):verify(data)

@pytest.mark.parametrize("key",list(m.ORDER))
def test_bool_status_never_equals_int_status(key):
    data=fixture();data[key]["status"]=True
    with pytest.raises(m.Denied):verify(data)

@pytest.mark.parametrize("field,value",[
    ("id",1414228002),("id",True),
    ("full_name","attacker/repository"),
    ("visibility","private"),("private",True),
    ("default_branch","develop")
])
def test_repo_identity_or_public_visibility_drift_denied(field,value):
    data=fixture();data["repository"]["body"][field]=value
    with pytest.raises(m.Denied):verify(data)

@pytest.mark.parametrize("key,value",[
    ("sha","0"*40),("sha",None)
])
def test_target_commit_wrong_denied(key,value):
    data=fixture();data["target"]["body"][key]=value
    with pytest.raises(m.Denied):verify(data)

def test_head_wrong_different_or_unpinned_denied():
    data=fixture();data["main"]["body"]["sha"]="a"*40
    with pytest.raises(m.Denied):verify(data)
    with pytest.raises(m.Denied):
        m.verify_five_exact_gets(data,expected_head=None)
    with pytest.raises(m.Denied):
        m.verify_five_exact_gets(data,expected_head="bad")

@pytest.mark.parametrize("key,value",[
    ("id",1),("enforcement","disabled"),
    ("updated_at","2026-10-11T22:01:00.000+09:00"),
    ("bypass_actors",[{"actor_id":1,"actor_type":"RepositoryRole"}]),
    ("rules",[{"type":"deletion"}]),
    ("conditions",{"ref_name":{"include":["refs/heads/main"],"exclude":[]}}),
    ("current_user_can_bypass","always")
])
def test_ruleset_authority_drift_denied(key,value):
    data=fixture();data["ruleset"]["body"][key]=value
    with pytest.raises(m.Denied):verify(data)

@pytest.mark.parametrize("value",[
    {"message":"Reference already exists"},
    {"message":"Not Found","ref":"refs/heads/main"},
    {"message":"Not Found","object":{"sha":"0"*40}},
    {},
])
def test_missing_ref_get_does_not_accept_ambiguous_payload(value):
    data=fixture();data["candidate"]["body"]=value
    with pytest.raises(m.Denied):verify(data)

@pytest.mark.parametrize("method,path",[
    ("POST",m.PATHS["candidate"]),("PUT",m.PATHS["target"]),
    ("DELETE",m.PATHS["ruleset"]),
    ("GET","/repos/"+m.REPO+"/git/refs"),
    ("GET","/repos/"+m.REPO+"/git/ref/heads/main"),
    ("GET","https://evil.example/"),
    ("PATCH","/repos/"+m.REPO),
])
def test_readonly_method_and_exact_path_only(method,path):
    with pytest.raises(m.Denied):m.validate_readonly_transport_request(method,path)

def test_readonly_gate_refuses_even_valid_token_and_fake_http(monkeypatch):
    def illegal(*args,**kwargs):
        pytest.fail("NO_NETWORK_IN_REVIEW_CI")
    monkeypatch.setattr(socket.socket,"connect",illegal)
    monkeypatch.setattr(socket.socket,"connect_ex",illegal)
    with pytest.raises(m.Denied):
        m.future_readonly_get_once("GET",m.PATHS["ruleset"],
                                  token="fake-github-token-123456")
    with pytest.raises(m.Denied):
        m.real_create_ref_once(token="fake-github-token-123456",role="A")

def test_contract_scope_and_report_hash():
    manifest=json.loads(m.CONTRACT.read_text(encoding="utf-8"))
    assert m.verify_contract(manifest)
    result=m.review()
    assert result["real_github_get_count"]==0
    assert result["real_github_post_count"]==0
    assert result["real_provider_post_count"]==0
    assert result["write_authorized"] is False
    assert result["verdict"]["write_authorized"] is False
    asserted=result.pop("report_sha256")
    assert m.sha(result)==asserted

def test_contract_extra_removed_or_pretended_approval_denied():
    manifest=json.loads(m.CONTRACT.read_text(encoding="utf-8"))
    for field,value in [
      ("separately_approved_workflow_sha","a"*40),
      ("signed_owner_approval_reference","old"),
      ("live_readonly_network_gate",True),
      ("live_create_ref_write_gate",True),
      ("real_cross_run_cas_proven",True),
      ("actual_github_post_count",1),
      ("provider_dispatch","ALLOW"),
    ]:
        d=deepcopy(manifest);d[field]=value
        with pytest.raises(m.Denied):m.verify_contract(d)
    d=deepcopy(manifest);d["new_unknown_field"]=True
    with pytest.raises(m.Denied):m.verify_contract(d)
    d=deepcopy(manifest);del d["api_paths"]
    with pytest.raises(m.Denied):m.verify_contract(d)

def test_unapproved_future_writer_workflow_does_not_exist():
    assert not m.ACTIVE_WRITER_WORKFLOW.exists()

def test_report_redirect_denied(tmp_path,monkeypatch):
    monkeypatch.setattr(m,"ROOT",tmp_path)
    with pytest.raises(m.Denied):
        m.main(["cmd",str(tmp_path/"wrong.json")])
