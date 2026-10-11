"""Offline mocks for actual manual #338 GitHub-hosted five-GET-only runner."""
from copy import deepcopy
import json
from pathlib import Path
import socket
import sys
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts import task4_338_live_authenticated_readonly_preflight_v1 as m

SHA="a"*40
def env():
    return {
      "GITHUB_REPOSITORY":m.REPO,
      "GITHUB_REPOSITORY_ID":str(m.REPO_ID),
      "GITHUB_REF":"refs/heads/main",
      "GITHUB_EVENT_NAME":"workflow_dispatch",
      "GITHUB_RUN_ATTEMPT":"1",
      "GITHUB_ACTOR":"veritasfuji-japan",
      "GITHUB_WORKFLOW_REF":m.REPO+"/.github/workflows/"+m.WORKFLOW+"@refs/heads/main",
      "GITHUB_SHA":SHA,
      "GITHUB_RUN_ID":"38144288405",
      "GH_TOKEN":"fake-test-github-short-lived-token",
      "OPENAI_API_KEY":"","TASK4_OPENAI_API_KEY":"",
      "ANTHROPIC_API_KEY":"","OPENAI_BASE_URL":"","VERITAS_DATABASE_URL":""
    }

def fixture():
    from scripts import task4_337_live_get_prewrite_boundary_review_only_v1 as old
    return old.synthetic_get_fixture(expected_head=SHA)

def test_frozen_contract_and_parent_write_gate():
    d=json.loads(m.CONTRACT.read_text(encoding="utf-8"))
    assert m.verify_contract(d) is True

def test_complete_mock_five_gets_is_never_authority():
    f=fixture()
    verdict=m.evaluate(f,expected_sha=SHA)
    assert verdict["ruleset_full_bypass_verified"] is True
    assert verdict["write_authorized"] is False
    assert verdict["real_cross_run_cas_proven"] is False
    r=m.build_report(f,head=SHA,env=env())
    assert r["actual_authenticated_get_count"]==5
    assert r["real_github_create_ref_post_count"]==0
    assert r["real_provider_post_count"]==0
    assert r["future_writer_authorized"] is False
    assert r["provider_dispatch"]=="DENY"

def test_hidden_bypass_never_inferred_empty():
    f=fixture()
    del f["ruleset"]["body"]["bypass_actors"]
    v=m.evaluate(f,expected_sha=SHA)
    assert v["classification"]=="FIVE_LIVE_GETS_BYPASS_VISIBILITY_INCOMPLETE"
    assert v["ruleset_bypass_list_visible"] is False
    assert v["ruleset_full_bypass_verified"] is False
    del f["ruleset"]["body"]["current_user_can_bypass"]
    assert m.evaluate(f,expected_sha=SHA)["ruleset_full_bypass_verified"] is False

@pytest.mark.parametrize("field,bad",[
    ("id",1),("full_name","other/repo"),("private",True),
    ("default_branch","dev"),("visibility","private")
])
def test_repo_identity_fail_closed(field,bad):
    f=fixture();f["repository"]["body"][field]=bad
    with pytest.raises(m.Denied):m.evaluate(f,expected_sha=SHA)

@pytest.mark.parametrize("name,bad",[
    ("repository",403),("main",404),("target",403),
    ("ruleset",403),("candidate",200),("candidate",422)
])
def test_unexpected_api_status_denied(name,bad):
    f=fixture();f[name]["status"]=bad
    with pytest.raises(m.Denied):m.evaluate(f,expected_sha=SHA)

@pytest.mark.parametrize("field,bad",[
    ("id",1),("updated_at","2026-10-11T23:00:00+09:00"),
    ("enforcement","disabled"),
    ("rules",[{"type":"deletion"}]),
    ("bypass_actors",[{"actor_id":1}]),
    ("current_user_can_bypass","always"),
    ("conditions",{"ref_name":{"include":["refs/heads/main"],"exclude":[]}})
])
def test_ruleset_changes_or_bypass_denied(field,bad):
    f=fixture();f["ruleset"]["body"][field]=bad
    with pytest.raises(m.Denied):m.evaluate(f,expected_sha=SHA)

@pytest.mark.parametrize("key,bad",[
    ("GITHUB_REPOSITORY","bad/name"),
    ("GITHUB_REPOSITORY_ID","12"),
    ("GITHUB_REF","refs/heads/other"),
    ("GITHUB_EVENT_NAME","pull_request"),
    ("GITHUB_RUN_ATTEMPT","2"),
    ("GITHUB_ACTOR","untrusted-account"),
    ("GITHUB_WORKFLOW_REF","bad/path"),
    ("GH_TOKEN",""),
    ("GITHUB_SHA","b"*40),
    ("OPENAI_API_KEY","secret"),
    ("ANTHROPIC_API_KEY","secret"),
])
def test_invalid_context_denied(key,bad):
    d=env();d[key]=bad
    with pytest.raises(m.Denied):m.verify_context(d,checkout_sha=SHA)

def test_no_extra_or_missing_receipts():
    f=fixture();f["unauthorized"]=f["repository"]
    with pytest.raises(m.Denied):m.evaluate(f,expected_sha=SHA)
    f=fixture();del f["main"]
    with pytest.raises(m.Denied):m.evaluate(f,expected_sha=SHA)

def test_untrusted_ref_or_target_denied():
    f=fixture();f["candidate"]["body"]={"message":"Not Found","ref":"refs/heads/main"}
    with pytest.raises(m.Denied):m.evaluate(f,expected_sha=SHA)
    f=fixture();f["target"]["body"]["sha"]="0"*40
    with pytest.raises(m.Denied):m.evaluate(f,expected_sha=SHA)

def test_exact_five_get_no_post_mock(monkeypatch):
    paths=[];methods=[]
    class FakeResponse:
        def __init__(self,path):
            f=fixture()
            key=next(k for k in m.KEYS if m.parent.PATHS[k]==path)
            self.status=f[key]["status"]
            self.body=json.dumps(f[key]["body"]).encode()
        def read(self,n):
            return self.body[:n]
    class Fake:
        def __init__(self,host,**kw):
            assert host=="api.github.com"
            self.path=None
        def request(self,method,path,**kw):
            methods.append(method);paths.append(path)
            assert method=="GET" and "Authorization" in kw.get("headers",{})
            self.path=path
        def getresponse(self):
            return FakeResponse(self.path)
        def close(self):pass
    def blocked(*a,**kw):pytest.fail("REAL_NETWORK_NOT_ALLOWED_IN_TEST")
    monkeypatch.setattr(socket.socket,"connect",blocked)
    r=m.run(env(),checkout_sha=SHA,transport_factory=Fake)
    assert methods==["GET"]*5
    assert paths==[m.parent.PATHS[k] for k in m.KEYS]
    assert r["actual_authenticated_get_count"]==5
    assert r["real_github_create_ref_post_count"]==0
    digest=r.pop("report_sha256")
    assert digest==m.digest(r)

def test_output_path_must_be_exact_new(tmp_path,monkeypatch):
    monkeypatch.setattr(m,"ROOT",tmp_path)
    with pytest.raises(m.Denied):m.main(["cli",str(tmp_path/"wrong.json")])

def test_auth_never_logs_token_or_raw_body():
    d=m.build_report(fixture(),head=SHA,env=env())
    s=json.dumps(d)
    assert env()["GH_TOKEN"] not in s
    assert '"body":' not in s
    assert '"Authorization":' not in s
