from fastapi import FastAPI
from pydantic import BaseModel
from agents.engine import AgentEngine, Incident

app = FastAPI(title="Silent Sentinel PoC")

engine = AgentEngine()

class IncidentCreate(BaseModel):
    source: str
    severity: float
    description: str

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/incidents")
def list_incidents():
    return engine.incidents

@app.post("/incidents")
def create_incident(payload: IncidentCreate):
    inc = Incident(
        source=payload.source,
        severity=payload.severity,
        description=payload.description
    )
    engine.register_incident(inc)
    return {"result": "created", "incident": inc.dict()}

@app.post("/agent/run")
def run_agent_once():
    result = engine.run_once()
    return {"result": result}
