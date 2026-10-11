"""#340: equal RFC3339 instants, never timestamp-drift tolerance or authority."""
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
BASE="2026-10-11T22:00:45.379+09:00"

def fixture():
    return m.parent.synthetic_get_fixture(expected_head=HEAD)

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
        "GITHUB_RUN_ID":"38145804543",
        "GH_TOKEN":"fake-token-used-in-offline-test-only",
        "OPENAI_API_KEY":"","TASK4_OPENAI_API_KEY":"",
        "ANTHROPIC_API_KEY":"","OPENAI_BASE_URL":"","VERITAS_DATABASE_URL":""
    }

@pytest.mark.parametrize("equivalent",[
    BASE,
    "2026-10-11T13:00:45.379Z",
    "2026-10-11T13:00:45.379+00:00",
    "2026-10-11T09:00:45.379-04:00",
    "2026-10-11T14:00:45.379+01:00",
    "2026-10-11T13:00:45.379000Z",
])
def test_exact_utc_instant_accepts_only_actual_equivalence(equivalent):
    assert m.same_exact_instant(equivalent,BASE) is True
    f=fixture()
    f["ruleset"]["body"]["updated_at"]=equivalent
    assert m.static_ruleset_drift_fields(f["ruleset"]["body"])==[]
    verdict=m.evaluate(f,expected_sha=HEAD)
    assert verdict["ruleset_updated_at_exact_instant_verified"] is True
    assert verdict["ruleset_updated_at_text_format_differs"]==(equivalent!=BASE)
    assert verdict["write_authorized"] is False
    assert verdict["real_cross_run_cas_proven"] is False

@pytest.mark.parametrize("invalid",[
    "2026-10-11T13:00:45Z",               # precision loss
    "2026-10-11T13:00:45.378999Z",        # 1 microsecond earlier
    "2026-10-11T13:00:45.379001Z",        # 1 microsecond later
    "2026-10-11T13:00:46.379Z",           # +1 second
    "2026-10-11T13:00:45.379+00:01",      # zone mismatch
    "2026-10-11T22:00:45.379Z",           # same wall clock, different instant
    "2026-10-11T13:00:45.379",            # timezone missing
    "2026-10-11 13:00:45.379Z",           # missing T
    "2026-10-11t13:00:45.379z",
    "2026-10-11T13:00:45.3790000Z",       # > 6 decimal digits
    "2026-10-11T13:00:45.379+14:01",      # invalid zone
    "2026-02-30T13:00:45.379Z",           # impossible date
    "2026-10-11T13:00:60.379Z",           # leap second unsupported
    "2026-10-11T13:00:45.379Z\n",
    "",
    None,
    False,
    123,
])
def test_non_equivalent_or_malformed_timestamp_fails_closed(invalid):
    assert m.same_exact_instant(invalid,BASE) is False
    f=fixture()
    f["ruleset"]["body"]["updated_at"]=invalid
    assert m.static_ruleset_drift_fields(f["ruleset"]["body"])==["updated_at:mismatch"]
    with pytest.raises(m.Denied,match="RULESET_STATIC_RULES_DRIFT"):
        m.evaluate(f,expected_sha=HEAD)

def test_missing_updated_at_is_not_equivalent_to_empty():
    f=fixture()
    del f["ruleset"]["body"]["updated_at"]
    assert m.static_ruleset_drift_fields(f["ruleset"]["body"])==["updated_at:missing"]
    with pytest.raises(m.Denied):
        m.evaluate(f,expected_sha=HEAD)

@pytest.mark.parametrize("key,value",[
    ("enforcement","disabled"),
    ("rules",[{"type":"deletion"}]),
    ("conditions",{"ref_name":{"include":["refs/heads/main"],"exclude":[]}}),
    ("source_type","Unknown"),
    ("bypass_actors",[{"actor_id":7}]),
    ("current_user_can_bypass","always")
])
def test_other_ruleset_security_fields_never_relaxed(key,value):
    f=fixture()
    f["ruleset"]["body"]["updated_at"]="2026-10-11T13:00:45.379Z"
    f["ruleset"]["body"][key]=value
    with pytest.raises(m.Denied):
        m.evaluate(f,expected_sha=HEAD)

def test_normalized_timestamp_does_not_promote_bypass_visibility():
    f=fixture()
    f["ruleset"]["body"]["updated_at"]="2026-10-11T13:00:45.379Z"
    del f["ruleset"]["body"]["bypass_actors"]
    verdict=m.evaluate(f,expected_sha=HEAD)
    assert verdict["ruleset_full_bypass_verified"] is False
    assert verdict["classification"]=="FIVE_LIVE_GETS_BYPASS_VISIBILITY_INCOMPLETE"
    assert verdict["write_authorized"] is False

def test_timestamp_mismatch_yields_hashed_negative_receipt_no_raw_body():
    f=fixture()
    f["ruleset"]["body"]["updated_at"]="2026-10-11T13:00:45.379001Z"
    report=m.failclosed_evidence(f,head=HEAD,env=context(),
                                 reason="RULESET_STATIC_RULES_DRIFT")
    report["report_sha256"]=m.digest(report)
    assert report["ruleset_static_drift_fields"]==["updated_at:mismatch"]
    assert report["verification_outcome"]=="FAIL_CLOSED"
    assert report["future_writer_authorized"] is False
    assert report["real_github_create_ref_post_count"]==0
    assert report["real_provider_post_count"]==0
    assert context()["GH_TOKEN"] not in json.dumps(report)
    assert "2026-10-11T13:00:45.379001Z" not in json.dumps(report)
    h=report.pop("report_sha256")
    assert m.digest(report)==h

def test_live_transport_mock_exact_five_get_only_without_real_network(monkeypatch):
    f=fixture()
    f["ruleset"]["body"]["updated_at"]="2026-10-11T13:00:45.379Z"
    used=[]
    class Reply:
        def __init__(self,key):
            self.status=f[key]["status"]
            self.body=json.dumps(f[key]["body"]).encode("utf-8")
        def read(self,size):
            return self.body[:size]
    class Transport:
        def __init__(self,host,**kwargs):
            assert host=="api.github.com"
        def request(self,method,path,**kwargs):
            assert method=="GET"
            assert path in m.parent.PATHS.values()
            used.append((method,path))
            self.key=next(k for k in m.KEYS if m.parent.PATHS[k]==path)
        def getresponse(self):
            return Reply(self.key)
        def close(self):pass
    def no_network(*args,**kwargs):
        pytest.fail("EXTERNAL_NETWORK_UNAUTHORIZED_IN_OFFLINE_TESTS")
    monkeypatch.setattr(socket.socket,"connect",no_network)
    monkeypatch.setattr(socket.socket,"connect_ex",no_network)
    report=m.run(context(),checkout_sha=HEAD,transport_factory=Transport)
    assert used==[("GET",m.parent.PATHS[k]) for k in m.KEYS]
    assert report["verification_outcome"]=="PASS_READONLY_ONLY"
    assert report["actual_authenticated_get_count"]==5
    assert report["verdict"]["ruleset_updated_at_exact_instant_verified"] is True
    assert report["verdict"]["ruleset_updated_at_text_format_differs"] is True
    assert report["future_writer_authorized"] is False
    assert report["real_github_create_ref_post_count"]==0
    assert report["real_provider_post_count"]==0
    report_hash=report.pop("report_sha256")
    assert report_hash==m.digest(report)
