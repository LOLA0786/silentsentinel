from pydantic import BaseModel
from typing import Optional, List
import time, random, asyncio

# import Guardian
from agents.zero_day.guardian import ZeroDayGuardian

# A lightweight InfraGraph import (assumes agents/graph/twin.py present)
from agents.graph.twin import InfraGraph

class Incident(BaseModel):
    id: str
    source: str
    severity: float
    description: str
    timestamp: float
    auto_remediated: bool = False
    remediation_notes: Optional[str] = None

class Engine:
    def __init__(self):
        self.incidents: List[Incident] = []
        self.counter = 0
        self.graph = InfraGraph()
        # start Zero-Day Guardian with short interval for demo (30s)
        self.zero_day = ZeroDayGuardian(self, poll_interval=30)
        self._running = True

    def _new_id(self):
        self.counter += 1
        return f"INC-{int(time.time())}-{self.counter}"

    def create_incident(self, source, severity, description):
        inc = Incident(
            id=self._new_id(),
            source=source,
            severity=severity,
            description=description,
            timestamp=time.time()
        )
        self.incidents.append(inc)
        return inc

    def manual_incident(self, source, severity, description):
        return self.create_incident(source, severity, description)

    def run_cycle(self):
        # existing hunter stub — create random incident for demo
        examples = [
            ("endpoint-1", "suspicious process spawn", 0.8),
            ("db-2", "credential brute force", 0.95),
            ("api-gateway", "data exfil pattern", 0.9),
            ("web-3", "low-entropy config change", 0.5),
            ("k8s-node-7", "suspicious kube exec", 0.92),
        ]
        src, desc, base = random.choice(examples)
        # severity randomization
        severity = round(min(0.999, base * random.uniform(0.9, 1.1)), 3)
        inc = self.create_incident(src, severity, desc)
        # update graph to link incident
        try:
            self.graph.apply_event(inc)
        except Exception:
            pass
        return {"log": {"source": src, "desc": desc, "base": base}, "severity": severity, "incident_id": inc.id}

    def remediate_by_id(self, incident_id: str):
        for inc in self.incidents:
            if inc.id == incident_id:
                inc.auto_remediated = True
                inc.remediation_notes = "manual remediation (simulated)"
                return True
        return False

    def graph_summary(self):
        return self.graph.summary()

    async def periodic_hunt(self):
        while self._running:
            self.run_cycle()
            await asyncio.sleep(8)

    async def shutdown(self):
        self._running = False
        try:
            self.zero_day.shutdown()
        except Exception:
            pass

    # --- AI Tier-2 Analyst Integration ---
    def analyze_incident(self, incident_id: str):
        from agents.analyst.tier2 import Tier2Analyst
        analyst = Tier2Analyst()

        # get incident
        target = None
        for i in self.incidents:
            if i.id == incident_id:
                target = i
                break
        if not target:
            return None

        # convert to dict
        target_dict = target.dict()
        related = [i.dict() for i in self.incidents]

        analysis = analyst.analyze(target_dict, related)
        # attach back to incident
        target.remediation_notes = "Analysis completed"
        return analysis

# integrate Tier-3 LLM analyst
def tier3_analyze(self, incident_id: str):
    try:
        from agents.analyst.tier3 import Tier3LLMAnalyst
    except Exception:
        return {"error": "tier3 module not available"}
    t3 = Tier3LLMAnalyst(self)
    return t3.analyze(incident_id)

# attach to Engine class
setattr(Engine, "tier3_analyze", tier3_analyze)
