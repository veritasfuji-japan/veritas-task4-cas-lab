"""Task4 #336 future workflow review: all roles disabled; no new live authorization."""
from copy import deepcopy
from pathlib import Path
import json
import socket
import sys
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts import task4_336_future_workflow_staged_review_only_v1 as m

def snapshot():
    return json.loads(m.CONTRACT.read_text(encoding="utf-8"))
def source():
    return (m.ROOT/m.TEMPLATE).read_text(encoding="utf-8")

def test_staged_review_remains_offline_and_no_real_authority():
    assert m.verify_contract(snapshot())
    assert m.verify_template(source())
    report=m.review()
    assert report["classification"]=="STAGED_TEMPLATE_OFFLINE_VALID_NOT_AN_ACTIVE_WORKFLOW"
    assert report["staged_jobs_all_hard_disabled"] is True
    assert report["real_writer_workflow_present"] is False
    assert report["actual_github_write_posts"]==report["provider_posts"]==0
    assert report["provider_dispatch"]=="DENY"
    sig=report.pop("report_sha256")
    assert m.digest(report)==sig

@pytest.mark.parametrize("key,value",[
    ("base_reviewed_main_sha","0"*40),
    ("repo","other/repo"),
    ("visibility","private"),
    ("ruleset_id",1),
    ("ruleset_enforcement","disabled"),
    ("ruleset_bypass_actors",[{"actor_id":1}]),
    ("frozen_ref","refs/heads/main"),
    ("frozen_target","0"*40),
    ("roles",["PREFLIGHT","A","B"]),
    ("future_max_distinct_runs",5),
    ("future_max_writer_post_count",3),
    ("future_max_posts_per_writer_run",2),
    ("retry_count",1),
    ("automatic_redispatch_allowed",True),
    ("proposed_total_runner_minutes_ceiling",128),
    ("concurrent_a_b_interleaving_attested",True),
    ("no_actions_concurrency_serializing_writers",False),
    ("workflow_template_installed",True),
    ("workflow_template_jobs_enabled",True),
    ("git_contents_write_workflow_installed",True),
    ("old_source_writer_gate_enabled",True),
    ("owner_future_write_approval","old token"),
    ("frozen_approved_writer_run_head_sha","f"*40),
    ("future_preflight_against_current_github_required",False),
    ("future_c_audit_distinct_job_required",False),
    ("future_422_conflict_requires_independent_corrobation",False),
    ("github_real_create_posts_in_this_pr",1),
    ("provider_posts_in_this_pr",1),
    ("real_github_cas_proven",True),
    ("immutable_single_use_authority_proven",True),
    ("existing_provider_dispatch","ALLOW"),
    ("state","AUTHORIZED")
])
def test_plan_drift_denied(key,value):
    changed=deepcopy(snapshot());changed[key]=value
    with pytest.raises(m.Denied):m.verify_contract(changed)

@pytest.mark.parametrize("old,new",[
    ("    if: ${{ false }}","    if: ${{ true }}"),
    ("      contents: write","      contents: read"),
    ("      contents: read","      contents: write"),
    ("          exit 78","          exit 0"),
    ("  writer-once:","  writer-twice:"),
    ("persist-credentials: false","persist-credentials: true"),
    ("    timeout-minutes: 8","    timeout-minutes: 60"),
    ("    runs-on: ubuntu-24.04","    runs-on: ubuntu-latest"),
    ("          - C","          - B"),
    ("      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262","      - uses: actions/checkout@v4"),
])
def test_attempt_to_enable_or_expand_template_denied(old,new):
    assert old in source()
    with pytest.raises(m.Denied):m.verify_template(source().replace(old,new,1))

@pytest.mark.parametrize("bad",[
    "secrets.MY_KEY", "github.token", "gh api ",
    "curl ", "https://api.github.com",
    "pull_request_target:", "\n  push:",
    "\nconcurrency:", "\n  concurrency:"
])
def test_no_hidden_network_pr_or_writer_serialization(bad):
    with pytest.raises(m.Denied):m.verify_template(source()+"\n"+bad)

def test_schema_missing_extra_and_invalid_denied():
    for bad in (None,False,[],12):
        with pytest.raises(m.Denied):m.verify_contract(bad)
    d=snapshot();d["approval_from_other_run"]=True
    with pytest.raises(m.Denied):m.verify_contract(d)
    d=snapshot();del d["frozen_ref"]
    with pytest.raises(m.Denied):m.verify_contract(d)

def test_network_and_write_disabled_with_forged_actor(monkeypatch):
    def blocked(*args,**kwargs):pytest.fail("NO_NETWORK")
    monkeypatch.setattr(socket.socket,"connect",blocked)
    monkeypatch.setattr(socket.socket,"connect_ex",blocked)
    with pytest.raises(m.Denied):m.staged_write_once(
         role="A",token="pretend",approved=True)
    assert m.review()["real_writer_workflow_present"] is False

def test_report_cannot_be_redirected(tmp_path,monkeypatch):
    monkeypatch.setattr(m,"ROOT",tmp_path)
    with pytest.raises(m.Denied):m.main(["program",str(tmp_path/"unsafe.json")])
