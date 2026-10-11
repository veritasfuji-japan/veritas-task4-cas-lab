"""#329 pure offline read-only plan tests: no GitHub ref or Provider actions."""
from copy import deepcopy
import json
from pathlib import Path
import socket
import sys
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts import task4_329_readonly_preflight_v1 as m

def test_fixed_lab_scope_and_zero_live_calls():
    assert m.check_static_identity()
    p=m.read_only_plan()
    assert p["scope_sha256"]==m.SCOPE_SHA256
    assert p["test_ref_proposal_only"]==m.REF
    assert p["actual_github_ref_writes"]==p["actual_github_api_calls"]==0
    assert p["actual_independent_actions_run_ids"]==[]
    for k in ("real_git_ref_cas_proven","separate_github_runners_observed",
              "immutable_ref_or_admin_separation_proven","new_live_provider_approval",
              "ref_creation_or_credential_use_approval",
              "billing_free_private_actions_minutes_verified"):
        assert p[k] is False
    assert p["real_provider_dispatch"]=="DENY"
    other=dict(p);h=other.pop("report_sha256")
    assert m.sha256(other)==h

def test_original_pins_do_not_confuse_lab_and_source():
    assert m.LAB=="veritasfuji-japan/veritas-task4-cas-lab"
    assert m.SOURCE=="veritasfuji-japan/rcc-revas-veritas-benchmark"
    assert m.LAB_INITIAL_MAIN=="058cae0a86fdceafdab8408c225f6059c40feb2b"
    assert m.SOURCE_MERGED_MAIN=="e3365d35054c06df09a37f3f4926bbe6c2fdba06"
    assert m.GET_PATH=="/repos/"+m.LAB+"/git/ref/"+m.REF.removeprefix("refs/")
    assert m.FUTURE_POST_PATH=="/repos/"+m.LAB+"/git/refs"

@pytest.mark.parametrize("bad",["refs/heads/feature","refs/tags/main","main",
        "refs/heads/MAIN","refs/heads/main\n","",None,True])
def test_nonmain_ref_denied(bad):
    with pytest.raises(m.Denied):m.read_only_plan(branch=bad)

@pytest.mark.parametrize("bad",["","0","a"*39,"A"*40,"g"*40,
                                 True,None,123,"a"*41])
def test_invalid_head_sha_denied(bad):
    with pytest.raises(m.Denied):m.read_only_plan(head_sha=bad)

def test_valid_updated_main_head_distinct_receipt_but_same_scope():
    a=m.read_only_plan(head_sha="a"*40);b=m.read_only_plan()
    assert a["checked_out_main_sha"]=="a"*40
    assert a["report_sha256"]!=b["report_sha256"]
    assert a["test_ref_proposal_only"]==b["test_ref_proposal_only"]

def test_perfectly_shaped_synthetic_claims_never_promote():
    rows=m.synthetic_events()
    assert [x["http_status"] for x in rows]==[201,422,422]
    assert m.check_synthetic_events(rows)=={
      "synthetic_fixture_shape_valid":True,
      "real_github_ref_cas_proven":False,
      "real_github_api_contacted":False,
      "real_provider_post_allowed":False
    }

@pytest.mark.parametrize("which,key,value",[
 (0,"http_status",422),(0,"http_status",True),
 (1,"http_status",409),(1,"outcome","validation_failed"),
 (2,"http_status",201),(2,"fake_run_id","A"),
 (0,"ref","refs/heads/main"),(0,"source","REAL_GITHUB"),
 (0,"provider_post_allowed",True),(0,"real_github_api_contacted",True),
 (1,"outcome","unknown")])
def test_forged_synthetic_evidence_fails_closed(which,key,value):
    rows=deepcopy(m.synthetic_events());rows[which][key]=value
    with pytest.raises(m.Denied):m.check_synthetic_events(rows)

@pytest.mark.parametrize("bad",[[],[{}],None,True,{},m.synthetic_events()[:2],
                                m.synthetic_events()+[{}]])
def test_incomplete_or_extra_fake_receipts_denied(bad):
    with pytest.raises(m.Denied):m.check_synthetic_events(bad)

def test_added_live_permission_fails_closed():
    rows=m.synthetic_events();rows[0]["new_live_permission"]=True
    with pytest.raises(m.Denied):m.check_synthetic_events(rows)

def test_report_new_file_only(tmp_path,monkeypatch):
    monkeypatch.setattr(m,"ROOT",tmp_path)
    dst=tmp_path/"results"/"task4-329-readonly-plan.json"
    report=m.write_report(dst,branch="refs/heads/main",head_sha=m.LAB_INITIAL_MAIN)
    assert json.loads(dst.read_text())["report_sha256"]==report["report_sha256"]
    with pytest.raises(m.Denied):
        m.write_report(dst,branch="refs/heads/main",head_sha=m.LAB_INITIAL_MAIN)
    with pytest.raises(m.Denied):
        m.write_report(tmp_path/"other.json",
                       branch="refs/heads/main",head_sha=m.LAB_INITIAL_MAIN)

def test_socket_connect_denied_during_preflight(monkeypatch):
    def forbid(*a,**k):pytest.fail("NO_NETWORK_PERMITTED")
    monkeypatch.setattr(socket.socket,"connect",forbid)
    monkeypatch.setattr(socket.socket,"connect_ex",forbid)
    assert m.read_only_plan()["actual_github_api_calls"]==0
    assert m.check_synthetic_events(m.synthetic_events())[
        "real_github_api_contacted"] is False

def test_contract_denies_real_write_scope_and_provider_claims():
    c=json.loads((ROOT/"contracts/TASK4_329_READONLY_LAB_PREFLIGHT_V1.json").read_text())
    assert c["rule_of_one"]==m.RULE
    assert c["scope_sha256"]==m.SCOPE_SHA256
    assert c["test_only_proposed_ref"]==m.REF
    assert c["readonly_ref_get_path"]==m.GET_PATH
    assert c["workflow_permissions"]=="contents:read"
    assert c["workflow_trigger"]=="MANUAL_ONLY_WORKFLOW_DISPATCH_AFTER_MERGE"
    for k in ("automatic_pr_ci_trigger","automatic_push_ci_trigger",
              "uses_owner_api_secrets","uses_github_write_token",
              "actual_remote_cas_proven","admin_immutability_proven",
              "private_actions_free_minutes_verified","new_owner_ref_write_approval",
              "new_owner_provider_spend_approval"):
        assert c[k] is False
    for k in ("actual_git_ref_writes","actual_github_api_probes",
              "observed_independent_workflow_runs","provider_posts",
              "new_model_scores","real_bank_effects"):
        assert c[k]==0
    assert c["provider_dispatch"]=="DENY"

def test_manual_only_workflow_no_privileged_execution():
    w=(ROOT/".github/workflows/task4-329-readonly-manual-preflight.yml").read_text()
    assert "workflow_dispatch:" in w
    assert "contents: read" in w
    assert "persist-credentials: false" in w
    for forbidden in ("pull_request:","pull_request_target:","push:",
        "repository_dispatch:","contents: write","secrets.",
        "gh api --method POST","git push","api.github.com"):
        assert forbidden not in w
    assert 'OPENAI_API_KEY: ""' in w
    s=(ROOT/"scripts/task4_329_readonly_preflight_v1.py").read_text()
    for forbidden in ("urllib.request","requests.post","httpx.post",
                      "HTTPConnection(","api.openai.com","git push","subprocess"):
        assert forbidden not in s
