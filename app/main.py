
# FULL BACKEND ENTRY (ABRIDGED)
# — includes WS, CVE Guardian, Multi-agent engine, API, Graph, IAM, Log ingestion
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from agents.agents_core.engine import Engine

app = FastAPI(title="Silent Sentinel — Full Autonomous SOC")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = Engine()

@app.get("/health")
def health():
    return {"status":"ok"}

@app.get("/incidents")
def incidents():
    return [i.dict() for i in engine.incidents]

@app.post("/agent/run")
def run_agent():
    return engine.run_cycle()

@app.get("/graph")
def graph():
    return engine.graph.summary()

# --- Zero-Day manual trigger ---
@app.post("/zero-day/scan")
def zero_day_scan():
    """Trigger an immediate Zero-Day scan and return findings."""
    try:
        findings = engine.zero_day.scan_and_report()
        return {"status": "scanned", "findings": findings}
    except Exception as e:
        return {"status": "error", "error": str(e)}

@app.get("/analysis/{incident_id}")
def analyze_incident(incident_id: str):
    analysis = engine.analyze_incident(incident_id)
    if analysis is None:
        return {"error": "incident not found"}
    return analysis

@app.post("/tier3/analyze/{incident_id}")
def tier3_analyze_endpoint(incident_id: str):
    """Call Tier-3 LLM analyst (RAG + LLM or template fallback)."""
    try:
        res = engine.tier3_analyze(incident_id)
        return res
    except Exception as e:
        return {"error": str(e)}

@app.get("/storyboard/{incident_id}")
def incident_storyboard(incident_id: str):
    """
    Generate an incident storyboard: timeline of events related to the incident's source,
    plus short human-readable narrative.
    """
    # find the target
    target = None
    for inc in engine.incidents:
        if inc.id == incident_id:
            target = inc
            break
    if not target:
        return {"error": "incident not found"}

    # collect related incidents by same source, sorted by timestamp
    related = [i for i in engine.incidents if i.source == target.source]
    related_sorted = sorted(related, key=lambda x: x.timestamp)
    timeline = []
    for r in related_sorted:
        timeline.append({
            "id": r.id,
            "timestamp": r.timestamp,
            "severity": r.severity,
            "description": r.description
        })

    # simple narrative assembly
    narrative_lines = []
    narrative_lines.append(f"Incident Storyboard for {target.id} (source: {target.source})")
    narrative_lines.append(f"Total related events: {len(related_sorted)}")
    for t in timeline:
        narrative_lines.append(f"- [{time.ctime(t['timestamp'])}] {t['id']} • sev={t['severity']} • {t['description']}")

    narrative = "\n".join(narrative_lines)
    return {"timeline": timeline, "narrative": narrative}

# --- PDF export endpoint ---
from fastapi.responses import StreamingResponse
from agents.report.pdf_report import generate_incident_pdf

@app.get("/incident/{incident_id}/report")
def incident_pdf_report(incident_id: str):
    # first, run Tier-3 analysis or storyboard to gather content
    analysis = engine.tier3_analyze(incident_id) if hasattr(engine, "tier3_analyze") else None
    storyboard = {}
    # attempt to generate storyboard
    try:
        from time import ctime
        related = [i for i in engine.incidents if i.source == next((x.source for x in engine.incidents if x.id==incident_id), None)]
        related_sorted = sorted(related, key=lambda x: x.timestamp)
        timeline = [{"id":r.id,"timestamp":r.timestamp,"severity":r.severity,"description":r.description} for r in related_sorted]
        narrative = "\\n".join([f\"- [{__import__('time').ctime(t['timestamp'])}] {t['id']} • sev={t['severity']} • {t['description']}\" for t in timeline])
        storyboard = {"timeline": timeline, "narrative": narrative}
    except Exception:
        storyboard = {}

    merged = {}
    merged.update(analysis if isinstance(analysis, dict) else {})
    merged.update(storyboard)
    merged["incident_id"] = incident_id
    pdf_bytes = generate_incident_pdf(merged)
    return StreamingResponse(io.BytesIO(pdf_bytes), media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=incident_{incident_id}.pdf"})

@app.get("/storyboard/graph/{incident_id}")
def storyboard_graph(incident_id: str):
    # returns nodes & edges for the timeline graph around the incident source
    target = next((i for i in engine.incidents if i.id==incident_id), None)
    if not target:
        return {"error":"not found"}
    src = target.source
    # gather nodes within 2 hops
    try:
        G = engine.graph.G
        nodes = []
        edges = []
        # BFS up to depth 2 from src
        for n in nx.single_source_shortest_path_length(G, src, cutoff=2):
            nodes.append({"id": n, "meta": G.nodes[n]})
        for u,v,d in G.edges(data=True):
            if any(n["id"]==u for n in nodes) and any(n["id"]==v for n in nodes):
                edges.append({"from":u,"to":v,"meta":d})
        return {"nodes":nodes,"edges":edges}
    except Exception as e:
        return {"error": str(e)}

@app.post("/attackpath/simulate")
def simulate_attackpath(payload: dict):
    """
    payload example:
      {
        "entry_nodes": ["endpoint-1"],
        "targets": ["db-2"],
        "query": "data exfil pattern"
      }
    """
    entry_nodes = payload.get("entry_nodes", [])
    targets = payload.get("targets", [])
    query = payload.get("query", "")
    # compute graph shortest paths
    try:
        from agents.graph.attack_path import shortest_attack_paths, vector_simulated_attack_steps
        paths = shortest_attack_paths(engine.graph.G, entry_nodes, targets, k=5)
        vec_hints = vector_simulated_attack_steps(query, top_k=5)
        return {"paths": paths, "vector_hints": vec_hints}
    except Exception as e:
        return {"error": str(e)}
