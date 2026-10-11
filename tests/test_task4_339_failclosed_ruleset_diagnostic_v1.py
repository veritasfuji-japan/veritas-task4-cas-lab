"""#339: authenticated GET failures must yield a hashed, safe, DENY artifact."""
from copy import deepcopy
import json
from pathlib import Path
import socket
import sys
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts import task4_338_live_authenticated_readonly_preflight_v1 as m

HEAD="a"*40

def context():
    return {
        "GITHUB_REPOSITORY":m.REPO,
        "GITHUB_REPOSITORY_ID":str(m.REPO_ID),
        "GITHUB_REF":"refs/heads/main",
        "GITHUB_EVENT_NAME":"workflow_dispatch",
        "GITHUB_RUN_ATTEMPT":"1",
        "GITHUB_ACTOR":"veritasfuji-japan",
        "GITHUB_WORKFLOW_REF":m.REPO+"/.github/workflows/"+m.WORKFLOW+"@refs/heads/main",
        "GITHUB_SHA":HEAD,
        "GITHUB_RUN_ID":"38145112044",
        "GH_TOKEN":"fake-private-token-not-to-be-recorded",
        "OPENAI_API_KEY":"","TASK4_OPENAI_API_KEY":"",
        "ANTHROPIC_API_KEY":"","OPENAI_BASE_URL":"","VERITAS_DATABASE_URL":""
    }

def fixture():
    return m.parent.synthetic_get_fixture(expected_head=HEAD)

def fake_run(cases,*,failed_key=None):
    seen=[]
    class Response:
        def __init__(self,key):
            self.status=cases[key]["status"]
            self.data=json.dumps(cases[key]["body"]).encode("utf-8")
        def read(self,n):
            return self.data[:n]
    class Transport:
        def __init__(self,host,**kwargs):
            assert host=="api.github.com"
            self.key=None
        def request(self,method,path,**kwargs):
            assert method=="GET"
            assert path in m.parent.PATHS.values()
            seen.append((method,path))
            self.key=next(key for key in m.KEYS if m.parent.PATHS[key]==path)
            if self.key==failed_key:
                raise OSError("synthetic transport interruption")
        def getresponse(self):
            return Response(self.key)
        def close(self):
            pass
    report=m.run(context(),checkout_sha=HEAD,transport_factory=Transport)
    expected=m.digest({k:v for k,v in report.items() if k!="report_sha256"})
    assert expected==report["report_sha256"]
    assert report["real_github_create_ref_post_count"]==0
    assert report["real_provider_post_count"]==0
    assert report["future_writer_authorized"] is False
    assert report["provider_dispatch"]=="DENY"
    assert context()["GH_TOKEN"] not in json.dumps(report)
    assert '"body":' not in json.dumps(report)
    assert len(seen)<=5
    assert [p for _,p in seen]==[m.parent.PATHS[k] for k in m.KEYS[:len(seen)]]
    return report

@pytest.mark.parametrize("field",[
    "id","name","target","source_type",
    "enforcement","updated_at","conditions","rules"
])
def test_ruleset_missing_fields_are_named_only(field):
    f=fixture()
    del f["ruleset"]["body"][field]
    result=fake_run(f)
    assert result["verification_outcome"]=="FAIL_CLOSED"
    assert result["failure_code"]=="RULESET_STATIC_RULES_DRIFT"
    assert result["ruleset_static_drift_fields"]==[field+":missing"]
    assert result["actual_authenticated_get_count"]==5
    assert set(result["http_statuses"])==set(m.KEYS)
    assert set(result["body_sha256"])==set(m.KEYS)

@pytest.mark.parametrize("field,value",[
    ("source_type","Untrusted"),("enforcement","disabled"),
    ("name","another-ruleset"),("updated_at","WRONG_TIMESTAMP"),
    ("conditions",{"ref_name":{"include":["refs/heads/main"],"exclude":[]}}),
    ("rules",[{"type":"deletion"}])
])
def test_ruleset_changed_values_denied_without_leaking_value(field,value):
    f=fixture()
    f["ruleset"]["body"][field]=value
    report=fake_run(f)
    assert report["verification_outcome"]=="FAIL_CLOSED"
    assert report["ruleset_static_drift_fields"]==[field+":mismatch"]
    assert str(value) not in json.dumps(report)

def test_multiple_drift_fields_are_individually_identified():
    f=fixture()
    del f["ruleset"]["body"]["source_type"]
    f["ruleset"]["body"]["updated_at"]="untrusted-value"
    r=fake_run(f)
    assert r["ruleset_static_drift_fields"]==[
        "source_type:missing","updated_at:mismatch"]
    assert "untrusted-value" not in json.dumps(r)

def test_bypass_visibility_missing_never_promoted():
    f=fixture()
    del f["ruleset"]["body"]["bypass_actors"]
    r=fake_run(f)
    assert r["verification_outcome"]=="PASS_READONLY_ONLY"
    assert r["verdict"]["ruleset_full_bypass_verified"] is False
    assert r["future_writer_authorized"] is False

def test_real_bypass_actor_causes_denial():
    f=fixture()
    f["ruleset"]["body"]["bypass_actors"]=[{"actor_id":1}]
    r=fake_run(f)
    assert r["verification_outcome"]=="FAIL_CLOSED"
    assert r["failure_code"]=="RULESET_BYPASS_NOT_EMPTY"

def test_ruleset_403_fails_closed_with_receipt():
    f=fixture()
    f["ruleset"]["status"]=403
    r=fake_run(f)
    assert r["verification_outcome"]=="FAIL_CLOSED"
    assert r["failure_code"]=="UNEXPECTED_GET_RESPONSE_ruleset"
    assert r["http_statuses"]["ruleset"]==403

def test_partial_transport_error_preserves_partial_get_statuses():
    r=fake_run(fixture(),failed_key="target")
    assert r["verification_outcome"]=="FAIL_CLOSED"
    assert r["failure_code"]=="GITHUB_GET_FAILED_CLOSED_target"
    assert r["actual_authenticated_get_count"]==2
    assert set(r["http_statuses"])=={"repository","main"}

def test_clean_mock_run_is_still_not_writer_authority():
    r=fake_run(fixture())
    assert r["verification_outcome"]=="PASS_READONLY_ONLY"
    assert r["failure_code"] is None
    assert r["ruleset_static_drift_fields"]==[]
    assert r["future_writer_authorized"] is False

def test_no_real_network_or_post_when_mocked(monkeypatch):
    def blocked(*args,**kwargs):
        pytest.fail("NO_REAL_NETWORK_IN_TESTS")
    monkeypatch.setattr(socket.socket,"connect",blocked)
    monkeypatch.setattr(socket.socket,"connect_ex",blocked)
    assert fake_run(fixture())["verification_outcome"]=="PASS_READONLY_ONLY"
