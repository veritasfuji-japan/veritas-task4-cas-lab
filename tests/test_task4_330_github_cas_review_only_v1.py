"""#330 exact GitHub CreateRef candidate: all live writing source-locked OFF."""
from __future__ import annotations
from copy import deepcopy
import json
from pathlib import Path
import socket
import sys

import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts import task4_330_github_create_ref_candidate_review_only_v1 as m

def test_live_git_ref_and_provider_locked_at_source():
    assert m.REAL_GITHUB_WRITE_SOURCE_GATE is False
    assert m.APPROVED_WORKFLOW_HEAD_SHA is None
    assert m.LIVE_PROVIDER_DISPATCH_ALLOWED is False
    assert m.LAB=="veritasfuji-japan/veritas-task4-cas-lab"
    assert m.TARGET_SHA==m.MERGED_LAB_MAIN
    assert m.EXPERIMENT_REF==(
      "refs/heads/offline-test-ledger/task4-329-de45893cb289d9bca20ab879ac6d2f73")
    assert m.POST_PATH=="/repos/"+m.LAB+"/git/refs"
    assert m.GET_PATH==("/repos/"+m.LAB+"/git/ref/"+
                         m.EXPERIMENT_REF.removeprefix("refs/"))
    assert m.proposed_request()=={"ref":m.EXPERIMENT_REF,"sha":m.MERGED_LAB_MAIN}

def test_no_real_network_possible_even_fake_approved_env_and_transport():
    calls=[]
    def malicious_factory(*args,**kw):
        calls.append((args,kw))
        pytest.fail("A REAL GITHUB TRANSPORT MUST NEVER BE CONSTRUCTED")
    fake_env={
        "GITHUB_REPOSITORY":m.LAB,
        "GITHUB_REF":"refs/heads/main",
        "GITHUB_EVENT_NAME":"workflow_dispatch",
        "GITHUB_RUN_ATTEMPT":"1",
        "GITHUB_RUN_ID":"38134631438",
        "GITHUB_SHA":m.MERGED_LAB_MAIN,
        "GITHUB_TOKEN":"ghs_example_not_real_token_random",
        "GITHUB_WORKFLOW_REF":m.LAB+"/.github/workflows/"
          "task4-330-authorized-create-ref.yml@refs/heads/main"
    }
    with pytest.raises(m.Denied,match="NOT_APPROVED_IN_SOURCE"):
        m.real_create_ref_once_under_future_authorization(
            env=fake_env,transport_factory=malicious_factory)
    assert calls==[]

def test_even_environment_mutation_cannot_open_source_gate(monkeypatch):
    monkeypatch.setenv("TASK4_330_AUTHORIZE_REAL_WRITE","YES")
    monkeypatch.setenv("GITHUB_TOKEN","fake-ghs-token-do-not-use")
    with pytest.raises(m.Denied,match="NOT_APPROVED_IN_SOURCE"):
        m.real_create_ref_once_under_future_authorization()

def test_fake_created_is_candidate_not_true_remote_proof():
    status,receipt=m.fake_scenarios()["mock_created"]
    c=m.classify_create_ref_response(status,receipt)
    assert c["classification"]=="CANDIDATE_CREATED_REQUIRES_INDEPENDENT_REAL_GET"
    assert c["real_github_evidence"] is False
    assert c["independent_real_get_required"] is True
    assert c["automated_post_retry_permitted"] is False
    assert c["live_provider_dispatch"] is False

@pytest.mark.parametrize("name",["mock_validation_error","mock_existing_ref_error"])
def test_never_claim_proven_duplicate_solely_from_422(name):
    status,body=m.fake_scenarios()[name]
    x=m.classify_create_ref_response(status,body)
    assert x["classification"]=="VALIDATION_OR_ALREADY_EXISTS_UNPROVEN"
    assert x["real_github_evidence"] is False
    assert x["automated_post_retry_permitted"] is False

@pytest.mark.parametrize("name,classification",[
  ("mock_created_wrong_ref","UNKNOWN_201_WRONG_REF_OR_TARGET"),
  ("mock_created_wrong_sha","UNKNOWN_201_WRONG_REF_OR_TARGET"),
  ("mock_conflict","UNKNOWN_CONFLICT_NO_RETRY"),
  ("mock_auth_denied","DENIED_TOKEN_OR_PERMISSION"),
  ("mock_server_error","UNKNOWN_SERVER_OR_NETWORK_NO_RETRY"),
  ("mock_timeout","UNKNOWN_INVALID_RESPONSE")
])
def test_error_untrusted_wrong_receipt_never_grants_rights(name,classification):
    status,body=m.fake_scenarios()[name]
    x=m.classify_create_ref_response(status,body)
    assert x["classification"]==classification
    assert not any(x[k] for k in ("real_github_evidence",
                                 "real_github_create_ref_authorized",
                                 "live_provider_dispatch",
                                 "automated_post_retry_permitted"))

@pytest.mark.parametrize("code,body",[
  (201,[]),(201,{"ref":"refs/heads/main","object":{"sha":m.TARGET_SHA}}),
  (201,{"ref":m.EXPERIMENT_REF,"object":{"sha":"0"*40}}),
  (201,{"ref":m.EXPERIMENT_REF,"object":[]}),
  (201,{}),("201",{}),(True,{}),
  (422,{"message":"Unprocessable Entity"}),
  (422,{"message":"Reference already exists"}),
  (409,{}),(429,{}),(502,None),(None,None)
])
def test_untrusted_http_never_promoted(code,body):
    x=m.classify_create_ref_response(code,body)
    assert x["real_github_evidence"] is False
    assert x["real_github_create_ref_authorized"] is False
    assert x["live_provider_dispatch"] is False
    assert x["automated_post_retry_permitted"] is False

def test_report_contains_no_synthetic_to_real_upgrade():
    report=m.offline_review_report()
    other=dict(report);signature=other.pop("report_sha256")
    assert m.digest(other)==signature
    assert report["source_gate_open"] is False
    assert report["available_source_workflow_contents_write"] is False
    assert report["actual_api_token_read"] is False
    assert report["actual_github_network_calls"]==0
    assert report["real_github_ref_create_calls"]==0
    assert report["real_provider_posts"]==0
    assert report["actual_independent_actions_run_ids"]==[]
    assert report["real_github_ref_cas_confirmed"] is False
    assert report["live_provider_dispatch"]=="DENY"
    for name,rec in report["scenarios"].items():
        assert rec["synthetic"] is True
        assert rec["real_github_evidence"] is False
        assert rec["provider_dispatch"] is False

def test_fresh_evidence_file_only(tmp_path,monkeypatch):
    monkeypatch.setattr(m,"ROOT",tmp_path)
    dest=tmp_path/"results"/"task4-330-review-only-report.json"
    x=m.write_report(dest)
    assert json.loads(dest.read_text())["report_sha256"]==x["report_sha256"]
    with pytest.raises(m.Denied):
        m.write_report(dest)
    with pytest.raises(m.Denied):
        m.write_report(tmp_path/"results"/"different.json")

def test_no_network_during_offline_review(monkeypatch):
    def fail(*args,**kwargs):pytest.fail("NETWORK_ACCESS_FORBIDDEN_IN_REVIEW")
    monkeypatch.setattr(socket.socket,"connect",fail)
    monkeypatch.setattr(socket.socket,"connect_ex",fail)
    assert m.offline_review_report()["real_github_ref_create_calls"]==0

def test_frozen_contract_confirms_separate_authorization_required():
    contract=json.loads((ROOT/"contracts/TASK4_330_GITHUB_CAS_REVIEW_ONLY_V1.json").read_text())
    assert contract["rule_of_one"]==m.RULE
    assert contract["candidate_ref"]==m.EXPERIMENT_REF
    assert contract["candidate_commit_sha"]==m.TARGET_SHA
    assert contract["lab_repo"]==m.LAB
    assert contract["source_base_merged_sha"]==m.SOURCE_MAIN
    for key in ("real_github_ref_writes_enabled",
                "real_github_ref_written",
                "github_contents_write_permission_granted",
                "write_workflow_active","two_distinct_github_actions_runs_observed",
                "real_github_ref_atomic_once_proven",
                "github_ref_immutable_proven",
                "new_specific_approval_for_github_ref_mutation",
                "fresh_live_provider_approval","private_actions_no_cost_guaranteed"):
        assert contract[key] is False
    assert contract["actual_github_api_post_count"]==0
    assert contract["actual_openai_api_post_count"]==0
    assert contract["provider_dispatch"]=="DENY"
    assert contract["review_only_workflow_permission"]=="contents:read"

def test_manual_readonly_workflow_never_auto_runs_or_grants_write():
    p=ROOT/".github/workflows/task4-330-review-only-manual.yml"
    w=p.read_text()
    assert "workflow_dispatch:" in w
    assert "contents: read" in w
    assert "persist-credentials: false" in w
    for disallowed in (
        "pull_request:","pull_request_target:","push:","repository_dispatch:",
        "contents: write","secrets.","git push","gh api --method POST"
    ):
        assert disallowed not in w
    assert not (ROOT/".github/workflows/task4-330-authorized-create-ref.yml").exists()
    assert 'OPENAI_API_KEY: ""' in w

def test_only_nonexecuting_template_mentions_future_write_workflow():
    template=ROOT/"docs/templates/task4-330-future-create-ref-WRITE-INERT.example.yml"
    assert template.is_file()
    text=template.read_text()
    assert "contents: write" in text
    assert "workflow_dispatch" in text
    assert "NOT_ACTIVATED" in text
    assert ".github/workflows" in text
