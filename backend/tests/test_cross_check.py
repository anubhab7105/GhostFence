from app.attack_lab.runner import cross_check


def test_sink_vs_decision_cross_check_mismatch():
    summary = {"sink_exposed_requests": 3, "timeline": [{"decision": "block"}]}
    assert cross_check(summary) is False


def test_sink_vs_decision_cross_check_ok():
    summary = {"sink_exposed_requests": 0, "timeline": [{"decision": "block"}]}
    assert cross_check(summary) is True