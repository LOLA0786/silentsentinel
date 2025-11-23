# Silent Sentinel — Autonomous AI SOC (PoC)

# 🛡️ Silent Sentinel  
### Autonomous AI SOC • Tier-3 LLM Analyst • Zero-Day Guardian • Attack-Path Simulator  
**A fully autonomous, AI-powered Security Operations Center (SOC) engine with live threat hunting, RAG-driven analysis, PDF reporting, digital-twin graphing, and attack-path simulation.**

Silent Sentinel transforms any defensive team into a **Tier-3+ SOC** by combining:

- **Autonomous Incident Detection**
- **AI Tier-2 Analyst (offline heuristics)**
- **AI Tier-3 Analyst with LLM + RAG (Pinecone vectors)**
- **Zero-Day Guardian (CVE scanner + impact analysis)**
- **Digital Twin Topology Graph**
- **Attack-Path Simulator (graph + vector hints)**
- **Incident Storyboard Timeline**
- **1-Click PDF Incident Reports**
- **Live Dashboard (React + Vite)**

---

## 🚀 Features

### 🔥 **Autonomous Threat Hunting**
- Synthetic log generator
- Incident scoring & enrichment
- Memory-based stateful Engine

### 🧠 **AI Analysts**
- **Tier-2 Analyst**  
  Rule-based expert heuristics (credential abuse, exfil, K8s, config anomalies)

- **Tier-3 Analyst**  
  Powered by OpenAI LLM + Pinecone RAG:  
  - Executive summaries  
  - Root cause analysis  
  - Remediation playbooks  
  - Detection rules  
  - Board-level summaries  

### 🕸 **Graph-Based Digital Twin**
- NetworkX-powered topology  
- Storyboard view  
- Subgraph extraction  
- Edge-level metadata

### 🔍 **Zero-Day Guardian**
- CVE feed scanning  
- Impact mapping to your graph  
- Severity scoring  
- Auto-seed RAG vectors

### 🔥 **Attack-Path Simulation**
Attack chain generation using:
- Shortest-path graph traversal  
- Vector similarity hints via Pinecone  
- Hybrid graph + semantic inference  

### 📄 **One-Click PDF Reports**
Generate real SOC-grade reports:
- Executive summary  
- Timeline  
- Root cause  
- Remediation steps  

### 💻 **Live Frontend Dashboard**
- React + Vite  
- Real-time incident list  
- Tier-3 Modal  
- PDF download  
- Storyboard Graph (vis-network)  
- Attack-Path Simulator panel  

---

## 📦 Tech Stack

### Backend
- Python 3.11  
- FastAPI  
- Uvicorn  
- NetworkX  
- Pinecone Vector DB  
- OpenAI LLM  
- ReportLab (PDF)  

### Frontend
- React 18  
- Vite  
- TailwindCSS  
- vis-network  
- Axios  

---

## 🗂️ Project Structure

.
