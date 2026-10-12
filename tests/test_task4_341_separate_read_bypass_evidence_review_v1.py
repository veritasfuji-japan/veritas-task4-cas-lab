"""#341: refuse to turn two read-only snapshots into runtime write authority."""
from copy import deepcopy
import json
from pathlib import Path
import socket
import sys
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts import task4_341_separate_read_bypass_evidence_review_only_v1 as m

def frozen():
    return json.loads(m.CONTRACT.read_text(encoding="utf-8"))

def test_frozen_snapshot_review_works_but_not_bypass_proof():
    assert m.verify(frozen()) is True
    d=m.review()
    assert d["offline_evidence_crosschecked"] is True
    assert d["source_ruleset_full_raw_body_verified"] is False
    assert d["bypass_at_original_actions_run_proven"] is False
    assert d["independent_signed_observer_attested"] is False
    assert d["observations_simultaneous_attested"] is False
    assert d["external_admin_custody_attested"] is False
    assert d["actual_github_get_count_in_this_review"]==0
    assert d["actual_github_write_count_in_this_review"]==0
    assert d["actual_provider_post_count_in_this_review"]==0
    assert d["write_authorized"] is False
    assert d["provider_dispatch"]=="DENY"
    h=d.pop("report_sha256")
    assert h==m.digest(d)

@pytest.mark.parametrize("key,value",[
    ("source_run_id",38186765876),
    ("source_job_id",114610648510),
    ("source_run_attempt",2),
    ("source_artifact_id",11719338462),
    ("source_artifact_zip_sha256","0"*64),
    ("source_report_file_sha256","0"*64),
    ("source_junit_testcases",303),
    ("source_run_conclusion","failure"),
    ("frozen_source_main_sha","0"*40),
    ("repository","other/repo"),
])
def test_provenance_pin_drift_denied(key,value):
    d=frozen();d[key]=value
    with pytest.raises(m.Denied):m.verify(d)

@pytest.mark.parametrize("key,value",[
    ("head_sha","0"*40),
    ("run_id","38186765876"),
    ("verification_outcome","FAIL_CLOSED"),
    ("future_writer_authorized",True),
    ("real_github_create_ref_post_count",1),
    ("provider_dispatch","ALLOW"),
    ("read_response_body_persisted",True),
    ("report_sha256","0"*64),
    ("actual_authenticated_get_count",4),
])
def test_observed_runner_report_tampering_denied(key,value):
    d=frozen();d["source_run_report"][key]=value
    with pytest.raises(m.Denied):m.verify(d)

@pytest.mark.parametrize("key,value",[
    ("ruleset_bypass_list_visible",True),
    ("ruleset_full_bypass_verified",True),
    ("real_cross_run_cas_proven",True),
    ("write_authorized",True),
    ("classification","FIVE_LIVE_GET_SHAPES_COMPLETE_NOT_AUTHORITY"),
])
def test_run_bypass_visibility_cannot_be_promoted(key,value):
    d=frozen();d["source_run_report"]["verdict"][key]=value
    with pytest.raises(m.Denied):m.verify(d)

@pytest.mark.parametrize("key,value",[
    ("bypass_actors",[{"actor_id":1,"actor_type":"RepositoryRole"}]),
    ("current_user_can_bypass","always"),
    ("updated_at","2026-10-11T22:00:45.380+09:00"),
    ("enforcement","disabled"),
    ("rules",[{"type":"deletion"}]),
    ("conditions",{"ref_name":{"include":["refs/heads/main"],"exclude":[]}}),
    ("id",123),
])
def test_separate_witness_authority_drift_denied(key,value):
    d=frozen();d["separate_ruleset_observation"]["ruleset_projection"][key]=value
    with pytest.raises(m.Denied):m.verify(d)

@pytest.mark.parametrize("key",[
    "observation_timestamp_attested","raw_response_signed",
    "observer_token_scope_attested","same_runner_as_source",
    "same_instant_as_source_attested"
])
def test_observer_provenance_must_remain_unattested(key):
    d=frozen();d["separate_ruleset_observation"][key]=True
    with pytest.raises(m.Denied):m.verify(d)

@pytest.mark.parametrize("key,value",[
    ("runtime_no_bypass_attested",True),
    ("raw_ruleset_http_body_digest_reconstructable",True),
    ("source_runner_bypass_list_observed",True),
    ("authorization_at_execution_attested",True),
    ("independent_admin_custody_attested",True),
    ("real_cross_run_cas_proven",True),
    ("irreversible_single_use_proven",True),
    ("future_writer_authorized",True),
    ("real_github_post_count",1),
    ("provider_dispatch","ALLOW"),
])
def test_bridge_can_never_claim_runtime_authority(key,value):
    d=frozen();d["bridge_claims"][key]=value
    with pytest.raises(m.Denied):m.verify(d)

def test_extra_or_missing_unapproved_field_denied():
    d=frozen();d["unexpected_approval"]=True
    with pytest.raises(m.Denied):m.verify(d)
    d=frozen();del d["bridge_claims"]
    with pytest.raises(m.Denied):m.verify(d)
    d=frozen();d["separate_ruleset_observation"]["ruleset_projection"]["surprise"]=True
    with pytest.raises(m.Denied):m.verify(d)

def test_frozen_source_run_does_not_equal_current_new_action_head():
    assert m.RUN_HEAD=="cd1d137da8af98620ddd59f9adc1bee889128955"
    assert frozen()["source_run_report"]["head_sha"]==m.RUN_HEAD
    assert frozen()["source_run_report"]["verdict"]["ruleset_bypass_list_visible"] is False

def test_no_network_no_provider_and_no_real_writer(monkeypatch):
    def reject(*args,**kwargs):pytest.fail("NO_NETWORK_ALLOWED_IN_341")
    monkeypatch.setattr(socket.socket,"connect",reject)
    monkeypatch.setattr(socket.socket,"connect_ex",reject)
    assert m.review()["write_authorized"] is False
    with pytest.raises(m.writer.Denied):
        m.writer.real_create_ref_once_under_future_authorization(env={})

def test_only_exact_new_output_filename(tmp_path,monkeypatch):
    monkeypatch.setattr(m,"ROOT",tmp_path)
    with pytest.raises(m.Denied):m.main(["cli",str(tmp_path/"bad.json")])
