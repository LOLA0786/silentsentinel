from pydantic import BaseModel
import time, random

class Incident(BaseModel):
    id: str | None = None
    source: str
    severity: float
    description: str
    timestamp: float | None = None
    auto_remediated: bool = False

class AgentEngine:
    def __init__(self):
        self.incidents = []
        self.counter = 0

    def ingest_logs(self):
        examples = [
            ("endpoint-1", "suspicious process spawn", 0.8),
            ("db-2", "credential brute force", 0.95),
            ("api-gateway", "data exfil pattern", 0.9),
            ("web-3", "low-entropy config change", 0.5)
        ]
        src, desc, score = random.choice(examples)
        return {"source": src, "desc": desc, "score": score}

    def score_log(self, log):
        return round(log["score"] * random.uniform(0.9, 1.1), 3)

    def create_incident(self, log, severity):
        self.counter += 1
        return Incident(
            id=f"INC-{int(time.time())}-{self.counter}",
            source=log["source"],
            severity=severity,
            description=log["desc"],
            timestamp=time.time()
        )

    def auto_remediate(self, incident):
        if incident.severity > 0.9:
            incident.auto_remediated = random.random() < 0.8
        return incident.auto_remediated

    def register_incident(self, incident):
        self.incidents.append(incident)

    def run_once(self):
        log = self.ingest_logs()
        sev = self.score_log(log)
        inc = self.create_incident(log, sev)
        self.auto_remediate(inc)
        self.register_incident(inc)
        return {
            "log": log,
            "severity": sev,
            "incident_id": inc.id,
            "auto_remediated": inc.auto_remediated
        }
