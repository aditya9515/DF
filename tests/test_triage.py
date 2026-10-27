from agent_forensics.analysis import analyze
from agent_forensics.triage import incident_report


def test_annotations_do_not_change_frozen_predictions():
    events = [
        {
            "type": "session_start",
            "event_id": "s:1",
            "sequence": 1,
            "payload": {
                "policy": {"allowed_tools": ["Read"], "available_tools": ["Read", "Send"], "canary": "TEST_MARKER"}
            },
        },
        {
            "type": "tool_request",
            "event_id": "s:2",
            "sequence": 2,
            "payload": {
                "op_id": "call",
                "name": "Send",
                "arguments": {"destination": "recipient@external.invalid", "message": "TEST_MARKER"},
            },
        },
        {
            "type": "model_response",
            "event_id": "s:3",
            "sequence": 3,
            "payload": {"message": {"content": "TEST_MARKER"}},
        },
    ]
    result = incident_report(events)
    assert result["detectors"] == analyze(events)
    assert {o["kind"] for o in result["observations"]} == {
        "destination_observed",
        "synthetic_marker_in_tool_arguments",
        "synthetic_marker_in_model_output",
    }
    assert not result["observations"][0]["simulated_execution_observed"]
    events.append(
        {"type": "tool_result", "event_id": "s:4", "sequence": 4, "payload": {"op_id": "call", "content": "simulated"}}
    )
    assert incident_report(events)["observations"][0]["simulated_execution_observed"]
