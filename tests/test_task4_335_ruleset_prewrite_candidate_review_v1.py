"""Task4 #335 ruleset snapshot exactness and no-live-write guarantees."""
from copy import deepcopy
import json
from pathlib import Path
import socket
import sys
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts import task4_335_ruleset_prewrite_candidate_review_only_v1 as m

def baseline(): return json.loads(m.CONTRACT.read_text(encoding="utf-8"))

def test_review_snapshot_complete_not_authority():
    p=baseline()
    assert m.verify_contract(p)
    assert m.verify_no_write()
    d=m.preview()
    assert d["github_ref_write_authorized"] is False
    assert d["github_create_post_count"]==d["provider_post_count"]==0
    assert d["four_independent_runs_observed"] is False
    assert d["future_live_ruleset_preflight_required"] is True
    assert d["provider_dispatch"]=="DENY"
    s=d.pop("report_sha256")
    assert m.sha256(d)==s

@pytest.mark.parametrize("field,value",[
 ("id",24880025),("name","different"),
 ("target","tag"),("source_type","Organization"),
 ("enforcement","disabled"),("enforcement","evaluate"),
 ("conditions",{"ref_name":{"include":["refs/heads/main"],"exclude":[]}}),
 ("conditions",{"ref_name":{"include":[m.REF],"exclude":["refs/heads/main"]}}),
 ("conditions",{"ref_name":{"include":["refs/heads/offline-test-ledger/*"],"exclude":[]}}),
 ("bypass_actors",[{"actor_id":1,"actor_type":"RepositoryRole","bypass_mode":"always"}]),
 ("rules",[{"type":"deletion"},{"type":"non_fast_forward"}]),
 ("rules",[{"type":"deletion"},{"type":"non_fast_forward"},{"type":"update"},{"type":"creation"}]),
 ("rules",[{"type":"deletion"},{"type":"non_fast_forward"},{"type":"update"},{"type":"pull_request"}]),
 ("current_user_can_bypass","always"),
 ("updated_at","2026-10-11T22:01:00.000+09:00")
])
def test_changed_ruleset_rejected(field,value):
    r=deepcopy(baseline()["ruleset"]);r[field]=value
    with pytest.raises(m.Denied):m.require_frozen_ruleset(r)

@pytest.mark.parametrize("key,value",[
 ("source_main_sha","0"*40),("lab_repository","other/lab"),
 ("visibility_at_review","private"),("exact_trial_ref","refs/heads/main"),
 ("fixed_existing_target_commit","f"*40),
 ("read_only_observed_ref_status",200),
 ("future_roles",["A","B","C"]),
 ("future_total_runs_cap",5),
 ("future_create_post_cap",3),
 ("future_create_post_per_writer_cap",2),
 ("future_retries_cap",1),
 ("role_a_b_distinct_runners_required",False),
 ("planned_max_runner_minutes_per_run",60),
 ("planned_runner_minutes_total",100),
 ("exact_approved_writer_head_sha","1"*40),
 ("new_owner_github_ref_write_consent",True),
 ("actual_github_post_count",1),
 ("actual_provider_post_count",1),
 ("real_github_cas_proven",True),
 ("independent_admin_irrevocability_proven",True),
 ("source_gate_enabled",True),
 ("writer_workflow_installed",True),
 ("provider_dispatch","ALLOW")
])
def test_unreviewed_scope_or_live_claim_denied(key,value):
    p=baseline();p[key]=value
    with pytest.raises(m.Denied):m.verify_contract(p)

def test_missing_or_new_keys_fail_closed():
    for bad in [None,[],True,""]:
        with pytest.raises(m.Denied):m.verify_contract(bad)
    d=baseline();d["legacy_approval"]=True
    with pytest.raises(m.Denied):m.verify_contract(d)
    d=baseline();del d["ruleset"]
    with pytest.raises(m.Denied):m.verify_contract(d)
    d=baseline();del d["ruleset"]["bypass_actors"]
    with pytest.raises(m.Denied):m.verify_contract(d)

def test_no_real_writer_even_if_github_token_supplied(monkeypatch):
    def fail(*args,**kwargs):pytest.fail("NO_SOCKET_CONNECT")
    monkeypatch.setattr(socket.socket,"connect",fail)
    monkeypatch.setattr(socket.socket,"connect_ex",fail)
    with pytest.raises(m.Denied):m.real_create_ref_once(
        env={"GITHUB_TOKEN":"fake-long-future-token","GITHUB_REF":"refs/heads/main"})
    assert m.preview()["github_create_post_count"]==0

def test_report_path_cannot_be_redirected(monkeypatch,tmp_path):
    monkeypatch.setattr(m,"ROOT",tmp_path)
    with pytest.raises(m.Denied):m.main(["program",str(tmp_path/"any.json")])
