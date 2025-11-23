from agents.engine import AgentEngine

def test_agent_cycle():
    engine = AgentEngine()
    before = len(engine.incidents)
    res = engine.run_once()
    assert "incident_id" in res
    assert len(engine.incidents) == before + 1
