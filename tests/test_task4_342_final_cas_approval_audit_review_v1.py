"""#342 negative tests: never promote reviewed plans into real CAS authority."""
from copy import deepcopy
import json
from pathlib import Path
import socket
import sys
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts import task4_342_final_cas_approval_audit_review_only_v1 as m

def frozen():
    return json.loads(m.CONTRACT.read_text(encoding="utf-8"))

def check_denied(value):
    with pytest.raises(m.Denied):
        m.verify(value)

def test_frozen_contract_review_never_grants_authority():
    d=frozen()
    assert m.verify(d) is True
    result=m.review()
    assert result["max_runs_planned_only"]==4
    assert result["max_posts_planned_only"]==2
    assert result["max_retries_planned_only"]==0
    assert result["explicit_owner_approval_present"] is False
    assert result["approved_exact_future_writer_workflow_sha"] is None
    assert result["github_ref_write_authorized"] is False
    assert result["real_writer_workflow_installed"] is False
    assert result["real_github_create_ref_posts_in_this_review"]==0
    assert result["real_provider_posts_in_this_review"]==0
    assert result["real_cross_run_cas_proven"] is False
    assert result["single_use_irrevocability_proven"] is False
    assert result["provider_dispatch"]=="DENY"
    sha=result.pop("report_sha256")
    assert m.digest(result)==sha

@pytest.mark.parametrize("field,value",[
    ("schema","future-executor"),
    ("rule_of_one","authorized"),
    ("repository","another/repo"),
    ("repository_id",1),
    ("visibility","private"),
    ("source_main_at_review","0"*40),
    ("planned_writer_workflow",".github/workflows/task4-342-enabled.yml"),
])
def test_top_level_pins_fail_closed(field,value):
    d=frozen();d[field]=value
    check_denied(d)

@pytest.mark.parametrize("field,value",[
    ("task4_340_run_id",0),
    ("task4_340_artifact_id",0),
    ("task4_340_artifact_zip_sha256","0"*64),
    ("task4_341_run_id",0),
    ("task4_341_job_id",0),
    ("task4_341_artifact_id",0),
    ("task4_341_artifact_zip_sha256","0"*64),
    ("task4_341_junit_passed",262),
    ("bypass_at_340_run_proven",True),
    ("independent_runtime_bypass_signed_attestation_present",True)
])
def test_evidence_claims_never_promoted(field,value):
    d=frozen();d["predecessor_evidence"][field]=value
    check_denied(d)

@pytest.mark.parametrize("field,value",[
    ("approved",True),
    ("approval_record_id","PR-merged-is-consent"),
    ("approval_record_sha256","0"*64),
    ("approved_exact_writer_workflow_head_sha","0"*40),
    ("approved_actor","veritasfuji-japan"),
    ("approved_repo_ref_target_tuple","unreviewed"),
    ("approval_expires_at","tomorrow"),
    ("approved_github_write_token_scope","contents:write"),
    ("approved_billing_max_usd",5),
    ("previous_api_or_pr_approval_reused",True),
    ("merge_or_ci_success_never_authorization",False),
])
def test_any_implicit_or_explicit_consent_claim_denied(field,value):
    d=frozen();d["explicit_separate_owner_consent"][field]=value
    check_denied(d)

@pytest.mark.parametrize("field,value",[
    ("roles",["PREFLIGHT","A","B","C","D"]),
    ("max_total_workflow_runs",5),
    ("max_total_create_ref_posts",3),
    ("max_posts_per_writer_role",2),
    ("max_retries",1),
    ("max_manual_replays",1),
    ("max_minutes_per_run",9),
    ("max_aggregate_runner_minutes",33),
    ("concurrent_writers_require_distinct_runs",False),
    ("concurrent_writers_require_distinct_jobs",False),
    ("concurrent_writers_require_separate_ephemeral_credentials",False),
    ("cross_run_temporal_overlap_must_be_observed",False),
    ("estimated_runtime_cost_not_authorized",False),
    ("writer_roles",["A","B","C"]),
    ("nonwriting_roles",["PREFLIGHT"])
])
def test_budget_or_run_independence_relaxation_denied(field,value):
    d=frozen();d["four_role_experiment_plan"][field]=value
    check_denied(d)

@pytest.mark.parametrize("field,value",[
    ("ref","refs/heads/main"),
    ("existing_target_commit_sha","0"*40),
    ("protected_ruleset_id",1),
    ("ruleset_updated_at","2026-10-11T22:00:45.380+09:00"),
    ("required_rules",["deletion"]),
    ("required_bypass_actors",[{"actor_id":1}]),
    ("required_current_user_can_bypass","always"),
    ("ruleset_not_admin_irrevocable",False),
    ("candidate_ref_404_at_separate_review",False),
    ("candidate_ref_absent_at_future_dispatch_unproven",False)
])
def test_target_ruleset_and_admin_limit_guard_denied(field,value):
    d=frozen();d["trial"][field]=value
    check_denied(d)

@pytest.mark.parametrize("field,value",[
    ("writer_workflow_installed",True),
    ("github_write_source_gate_enabled",True),
    ("approved_workflow_head_sha","0"*40),
    ("privileged_token_granted",True),
    ("owner_approval_present",True),
    ("independent_signed_auditor_present",True),
    ("actual_github_create_ref_post_count",1),
    ("actual_provider_post_count",1),
    ("real_cross_run_cas_proven",True),
    ("admin_irrevocable_one_time_consumption_proven",True),
    ("provider_dispatch","ALLOW"),
    ("final_classification","PROVEN")
])
def test_current_state_false_authority_proofs_denied(field,value):
    d=frozen();d["current_state"][field]=value
    check_denied(d)

@pytest.mark.parametrize("field",[
    "dispatch_gates_required","required_independent_audit_evidence",
    "forbidden_proof_promotions"
])
def test_no_dropped_ordered_security_requirements(field):
    d=frozen();d[field]=d[field][1:]
    check_denied(d)
    d=frozen();d[field]=d[field]+["UNREVIEWED_ITEM"]
    check_denied(d)

def test_added_or_missing_fields_not_implicitly_accepted():
    d=frozen();d["unreviewed_approval"]=True
    check_denied(d)
    d=frozen();del d["explicit_separate_owner_consent"]
    check_denied(d)
    d=frozen();d["trial"]["unreviewed_wider_ref"]=True
    check_denied(d)

def test_type_confusion_bool_vs_int_is_rejected():
    d=frozen();d["repository_id"]=True
    check_denied(d)
    d=frozen();d["current_state"]["actual_github_create_ref_post_count"]=False
    check_denied(d)

def test_closed_source_gate_cannot_be_overridden_even_with_contract(monkeypatch):
    assert m.verify_no_write_source() is True
    monkeypatch.setattr(m.source,"REAL_GITHUB_WRITE_SOURCE_GATE",True)
    with pytest.raises(m.Denied):
        m.verify(frozen())

def test_no_real_network_or_post_during_review(monkeypatch):
    def stop(*args,**kwargs):pytest.fail("NETWORK_NOT_ALLOWED_FOR_TASK4_342")
    monkeypatch.setattr(socket.socket,"connect",stop)
    monkeypatch.setattr(socket.socket,"connect_ex",stop)
    assert m.review()["github_ref_write_authorized"] is False
    with pytest.raises(m.Denied,match="NO_REAL_GITHUB_CREATE_REF_DISPATCH"):
        m.real_cas_dispatch("A")
    with pytest.raises(m.source.Denied):
        m.source.real_create_ref_once_under_future_authorization(env={})

def test_output_must_use_exact_new_fixed_path(tmp_path,monkeypatch):
    monkeypatch.setattr(m,"ROOT",tmp_path)
    with pytest.raises(m.Denied):
        m.main(["script",str(tmp_path/"wrong.json")])
