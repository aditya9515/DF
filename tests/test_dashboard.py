from streamlit.testing.v1 import AppTest
from agent_forensics.common import ROOT


def test_dashboard_session_and_findings():
    app = AppTest.from_file(str(ROOT / "src/agent_forensics/dashboard.py")).run(timeout=45)
    assert not app.exception
    assert app.title[0].value == "AI Agent Forensics & Audit Platform"
    assert len(app.dataframe) >= 1
    app.text_input[0].set_value("no-such-session").run()
    assert not app.exception
    assert any("No matching" in item.value for item in app.warning)
