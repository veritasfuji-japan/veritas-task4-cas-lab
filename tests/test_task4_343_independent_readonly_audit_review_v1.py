"""#343: an audit protocol is NEVER itself a signed runtime witness."""
import json
from pathlib import Path
import socket
import sys
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts import task4_343_independent_readonly_audit_review_only_v1 as m

def frozen():
    return json.loads(m.CONTRACT.read_text(encoding="utf-8"))

def denial(changed):
    with pytest.raises(m.Denied):
        m.verify(changed)

def test_exact_plan_and_report_remain_no_write():
    assert m.verify(frozen()) is True
    d=m.review()
    assert d["manifest_sha256"]==m.EXPECTED_CONTRACT_SHA256
    assert d["prior_run_342_id"]==38188332277
    assert d["independent_observer_connected"] is False
    assert d["cryptographic_signature_verification_implemented"] is False
    assert d["trust_root_public_key_pinned"] is False
    assert d["real_signed_receipts_observed"]==0
    assert d["same_run_signed_ruleset_bypass_attested"] is False
    assert d["clock_skew_or_capture_lag_approved"] is False
    assert d["admin_irrevocability_proven"] is False
    assert d["real_cross_run_cas_proven"] is False
    assert d["github_write_authorized"] is False
    assert d["real_github_get_count_in_this_review"]==0
    assert d["real_github_create_ref_posts_in_this_review"]==0
    assert d["real_provider_posts_in_this_review"]==0
    assert d["provider_dispatch"]=="DENY"
    h=d.pop("report_sha256")
    assert h==m.digest(d)

@pytest.mark.parametrize("field,value",[
    ("schema","future-live-observer"),
    ("rule_of_one","AUTHORIZED"),
    ("repository","other/repo"),
    ("repository_id",True),
    ("source_main_at_review","0"*40),
])
def test_root_schema_repo_and_head_locked(field,value):
    d=frozen();d[field]=value
    denial(d)

@pytest.mark.parametrize("field,value",[
    ("task4_340_real_readonly_run_id",0),
    ("task4_340_artifact_id",0),
    ("task4_340_zip_sha256","0"*64),
    ("task4_341_offline_review_run_id",0),
    ("task4_341_artifact_id",0),
    ("task4_341_zip_sha256","0"*64),
    ("task4_342_offline_plan_run_id",0),
    ("task4_342_job_id",0),
    ("task4_342_source_sha","0"*40),
    ("task4_342_artifact_id",0),
    ("task4_342_zip_sha256","0"*64),
    ("same_run_bypass_proven",True),
    ("real_cas_proven",True)
])
def test_cannot_rewrite_prior_evidence(field,value):
    d=frozen();d["prior_evidence"][field]=value
    denial(d)

@pytest.mark.parametrize("field,value",[
    ("ref","refs/heads/main"),
    ("target_commit_sha","0"*40),
    ("ruleset_id",42),
    ("frozen_ruleset_updated_at","2026-10-11T22:00:46.379+09:00"),
    ("allowed_writer_roles",["A","B","C"]),
    ("nonwriter_roles",[]),
    ("planned_max_create_ref_post_count",3),
    ("planned_max_per_writer_post_count",2),
    ("planned_max_retries",1)
])
def test_fixed_ref_post_budget_and_roles(field,value):
    d=frozen();d["immutable_trial_tuple"][field]=value
    denial(d)

@pytest.mark.parametrize("field,value",[
    ("separate_principal_from_writers",False),
    ("read_only_observer_capability_only",False),
    ("observer_identity_bound_to_signed_receipt",False),
    ("independent_credential_owner_required",False),
    ("credential_no_contents_write",False),
    ("credential_no_actions_write",False),
    ("independent_key_custody_outside_target_repo",False),
    ("signature_scheme_planned","HMAC-with-writer-secret"),
    ("signed_observer_attestation_trust_root_pinned",True),
    ("public_verification_key_sha256","0"*64),
    ("signature_verification_implemented",True),
    ("observer_app_or_external_auditor_connected",True),
    ("observer_identity_attested",True),
    ("observation_time_attested",True),
    ("credential_scope_attested",True),
    ("do_not_embed_secrets_in_artifact",False),
    ("same_actions_token_not_independent",False),
    ("repo_admin_can_edit_ruleset",False)
])
def test_no_fake_independent_observer_or_weaker_credentials(field,value):
    d=frozen();d["independent_observer_requirements"][field]=value
    denial(d)

@pytest.mark.parametrize("field,value",[
    ("max_clock_skew_ms",5000),
    ("max_capture_age_before_post_ms",60000),
    ("max_audit_capture_lag_ms",1000),
    ("thresholds_owner_approved",True),
    ("require_signed_receipt_linkage",False),
    ("require_git_sha_and_run_job_ids",False),
    ("require_server_state_and_post_receipts",False),
    ("require_proven_cross_run_overlap_for_race_claim",False),
    ("require_ruleset_bypass_visibility_at_attempt",False)
])
def test_no_unreviewed_timing_threshold_or_proof_relaxation(field,value):
    d=frozen();d["integrity_and_timing_constraints"][field]=value
    denial(d)

@pytest.mark.parametrize("field,value",[
    ("signature_scheme_implemented",True),
    ("observer_integrated",True),
    ("independent_receipt_count",1),
    ("signing_key_pinned",True),
    ("consent_for_github_write",True),
    ("writer_workflow_installed",True),
    ("read_only_workflow_only",False),
    ("real_github_create_ref_posts",1),
    ("provider_api_posts",1),
    ("real_cross_run_cas_proven",True),
    ("admin_irrevocable_single_use_proven",True),
    ("provider_dispatch","ALLOW"),
    ("classification","PROVEN")
])
def test_no_synthetic_receipt_or_proof_promotion(field,value):
    d=frozen();d["design_state"][field]=value
    denial(d)

@pytest.mark.parametrize("field",[
    "required_signed_receipt_fields",
    "audit_capture_phases",
    "mandatory_failure_conditions"
])
def test_signed_receipt_field_and_failure_list_complete(field):
    d=frozen();d[field].pop()
    denial(d)
    d=frozen();d[field].append("NEW_UNREVIEWED_ITEM")
    denial(d)

def test_extra_or_missing_manifest_field_is_denied():
    d=frozen();d["signed_execution_authorization"]=True
    denial(d)
    d=frozen();d.pop("independent_observer_requirements")
    denial(d)
    d=frozen();d["design_state"]["extra_claim"]=True
    denial(d)

def test_hypothetical_signature_and_fake_trust_root_not_accepted():
    fake={
        "schema":"future-signed-receipt",
        "observer_principal_id":"third-party",
        "bypass_fields_visible":True,
        "detached_signature":"pretend-signature",
        "github_ref_http_status":404,
        "workflow_run_id":38188332277
    }
    with pytest.raises(m.Denied,match="TRUST_ROOT_AND_OBSERVER_NOT_INSTALLED"):
        m.assess_future_signed_receipt(receipt=fake,trust_root=b"fake-key")
    with pytest.raises(m.Denied):
        m.assess_future_signed_receipt(receipt=None,trust_root=None)

def test_no_real_network_and_no_github_post_even_if_requested(monkeypatch):
    def refuse(*a,**kw):
        pytest.fail("TASK4_343_OUTBOUND_NETWORK_UNAUTHORIZED")
    monkeypatch.setattr(socket.socket,"connect",refuse)
    monkeypatch.setattr(socket.socket,"connect_ex",refuse)
    assert m.review()["github_write_authorized"] is False
    with pytest.raises(m.Denied,match="NO_REAL_GITHUB_CREATE_REF_AUTHORIZED"):
        m.attempt_real_create_ref(role="A",post=True)
    with pytest.raises(m.writer.Denied):
        m.writer.real_create_ref_once_under_future_authorization(env={})

def test_source_gate_must_stay_denied(monkeypatch):
    monkeypatch.setattr(m.writer,"REAL_GITHUB_WRITE_SOURCE_GATE",True)
    with pytest.raises(m.Denied):
        m.verify(frozen())

def test_bad_fixed_report_output_path(tmp_path,monkeypatch):
    monkeypatch.setattr(m,"ROOT",tmp_path)
    with pytest.raises(m.Denied):
        m.main(["script",str(tmp_path/"wrong.json")])
