"""
Tier-3 LLM Analyst with simple RAG (TF-IDF retriever) and optional OpenAI LLM adapter.

- If environment var OPENAI_API_KEY is set and openai is installable, the module will call OpenAI's
  chat completions to generate rich narratives.
- If not, a deterministic template-based response is produced using retrieved context.
- Retriever: TF-IDF over local corpus (incidents, graph node meta, cve feed).
"""

import os
import time
import json
from typing import List, Dict, Optional
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# optional import; if not available or no API key, we'll fallback
try:
    import openai
except Exception:
    openai = None

# small helper to build a textual corpus from engine state
def _build_corpus(engine) -> List[str]:
    corpus = []
    meta_map = []  # map index -> (type, id, source)
    # incidents
    for inc in engine.incidents:
        txt = f"INCIDENT {inc.id} | source: {inc.source} | severity: {inc.severity} | desc: {inc.description}"
        corpus.append(txt)
        meta_map.append(("incident", inc.id, inc.source))
    # graph nodes
    try:
        for n, meta in engine.graph.G.nodes(data=True):
            txt = f"NODE {n} | meta: {json.dumps(meta)}"
            corpus.append(txt)
            meta_map.append(("node", n, meta.get("type")))
    except Exception:
        pass
    # CVE feed if present
    try:
        with open("agents/zero_day/cve_feed.json","r") as f:
            feed = json.load(f)
            for e in feed:
                txt = f"CVE {e.get('cve_id')} | package: {e.get('package')} | cvss: {e.get('cvss')} | desc: {e.get('description')}"
                corpus.append(txt)
                meta_map.append(("cve", e.get("cve_id"), e.get("package")))
    except Exception:
        pass
    return corpus, meta_map

class SimpleRetriever:
    def __init__(self):
        self.vectorizer = None
        self.tfidf = None
        self.meta_map = []

    def fit(self, corpus: List[str], meta_map: List[tuple]):
        if not corpus:
            self.vectorizer = None
            self.tfidf = None
            self.meta_map = []
            return
        self.vectorizer = TfidfVectorizer(stop_words="english", max_features=2000)
        self.tfidf = self.vectorizer.fit_transform(corpus)
        self.meta_map = meta_map

    def query(self, q: str, top_k: int = 4):
        if self.tfidf is None:
            return []
        q_vec = self.vectorizer.transform([q])
        sims = cosine_similarity(q_vec, self.tfidf)[0]
        # top indices
        idxs = sims.argsort()[::-1][:top_k]
        results = []
        for i in idxs:
            results.append({"score": float(sims[i]), "meta": self.meta_map[i]})
        return results

class Tier3LLMAnalyst:
    def __init__(self, engine):
        self.engine = engine
        self.retriever = SimpleRetriever()
        self._refresh_index()

        # configure openai if available
        api_key = os.getenv("OPENAI_API_KEY")
        if api_key and openai is not None:
            openai.api_key = api_key
            self.use_openai = True
        else:
            self.use_openai = False

    def _refresh_index(self):
        corpus, meta_map = _build_corpus(self.engine)
        self.retriever.fit(corpus, meta_map)

    def _gather_context(self, incident_id: str, top_k: int = 4) -> List[str]:
        # refresh index then search by incident description text
        self._refresh_index()
        inc_obj = None
        for inc in self.engine.incidents:
            if inc.id == incident_id:
                inc_obj = inc
                break
        if not inc_obj:
            return []
        query = f"{inc_obj.description} {inc_obj.source} severity {inc_obj.severity}"
        hits = self.retriever.query(query, top_k=top_k)
        ctx = []
        for h in hits:
            typ, id_or_node, src = h["meta"]
            if typ == "incident":
                # find the incident text
                for inc in self.engine.incidents:
                    if inc.id == id_or_node:
                        ctx.append(f"INCIDENT {inc.id}: {inc.description} (severity {inc.severity})")
                        break
            elif typ == "node":
                ctx.append(f"NODE {id_or_node}: {src}")
            elif typ == "cve":
                # load CVE details if available
                try:
                    with open("agents/zero_day/cve_feed.json","r") as f:
                        feed = json.load(f)
                    for e in feed:
                        if e.get("cve_id") == id_or_node:
                            ctx.append(f"CVE {e.get('cve_id')}: {e.get('description')} (cvss {e.get('cvss')})")
                except Exception:
                    pass
        return ctx

    def _compose_prompt(self, incident, context_snippets: List[str]) -> str:
        # Compose a RAG prompt that is safe & useful
        ctx_text = "\n\n".join(context_snippets) if context_snippets else "No additional context."
        prompt = f\"\"\"You are a senior SOC analyst. Given the following incident, produce:
1) a short Executive Summary (2-3 sentences);
2) a technical Root Cause Hypothesis;
3) Step-by-step Remediation Playbook (clear commands/actions, prioritized);
4) Suggested Detection rules to prevent recurrence;
5) A short 3-line Board-ready summary.

INCIDENT:
ID: {incident.id}
Source: {incident.source}
Severity: {incident.severity}
Description: {incident.description}

CONTEXT:
{ctx_text}

Answer in JSON with keys: executive_summary, root_cause, remediation_playbook, detection_rules, board_summary.
\"\"\"
        return prompt

    def _call_openai(self, prompt: str) -> dict:
        # best-effort ChatCompletion call
        resp = openai.ChatCompletion.create(
            model="gpt-4o-mini",
            messages=[{"role":"system","content":"You are an expert SOC analyst."},
                      {"role":"user","content": prompt}],
            temperature=0.0,
            max_tokens=800
        )
        text = resp["choices"][0]["message"]["content"]
        # attempt to parse JSON from response; if fails, wrap in text
        try:
            import json
            return json.loads(text)
        except Exception:
            return {"text": text}

    def analyze(self, incident_id: str) -> Dict:
        # find incident
        target = None
        for inc in self.engine.incidents:
            if inc.id == incident_id:
                target = inc
                break
        if not target:
            return {"error": "incident not found"}

        context = self._gather_context(incident_id, top_k=6)
        prompt = self._compose_prompt(target, context)

        if self.use_openai:
            try:
                out = self._call_openai(prompt)
                return {"mode":"llm", "analysis": out, "context": context}
            except Exception as e:
                # fallback to template
                return {"mode":"llm_error_fallback", "error": str(e), "analysis": self._template_response(target, context), "context": context}
        else:
            return {"mode":"template", "analysis": self._template_response(target, context), "context": context}

    def _template_response(self, incident, context) -> Dict:
        # Deterministic high-quality template (no external LLM)
        exec_sum = f"Potential security event on {incident.source}. Severity {incident.severity}. Key observation: {incident.description}"
        root = "Root cause unknown; requires investigation. Suspected vectors: network intrusion, compromised credentials, or misconfiguration."
        remediation = [
            "Isolate affected host",
            "Collect forensic logs (sysmon/auditd, network captures)",
            "Rotate credentials and secrets associated with the source",
            "Apply vendor patches if applicable",
        ]
        detection = [
            "Create alert for repeated failed auth attempts from same source",
            "Monitor large outbound transfers from the host",
            "Enforce MFA and session revocation for suspicious users"
        ]
        board = f"{incident.source}: {incident.description} — Se {incident.severity}"
        return {
            "executive_summary": exec_sum,
            "root_cause": root,
            "remediation_playbook": remediation,
            "detection_rules": detection,
            "board_summary": board,
            "context_snippets": context
        }
