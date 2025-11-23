import React, {useState} from "react";
import Modal from "react-modal";
import axios from "axios";
import { saveAs } from "file-saver";

Modal.setAppElement("#root");

export default function Tier3Modal({isOpen,onClose,incidentId}){
  const [loading,setLoading] = useState(false);
  const [result,setResult] = useState(null);

  async function runTier3(){
    setLoading(true);
    try{
      const res = await axios.post(`http://127.0.0.1:8000/tier3/analyze/${incidentId}`);
      setResult(res.data);
    }catch(e){
      setResult({error: e.toString()});
    } finally { setLoading(false) }
  }

  async function downloadPDF(){
    const res = await axios.get(`http://127.0.0.1:8000/incident/${incidentId}/report`, { responseType: 'blob' });
    saveAs(res.data, `incident_${incidentId}.pdf`);
  }

  return (
    <Modal isOpen={isOpen} onRequestClose={onClose} contentLabel="Tier-3 Analysis" style={{content:{background:'#0b1220', color:'#e6eef8', maxWidth:800, margin:'auto'}}}>
      <h2>Tier-3 Analysis — {incidentId}</h2>
      <div style={{marginBottom:12}}>
        <button onClick={runTier3} className="px-3 py-1 bg-indigo-600 rounded mr-2">Run Tier-3</button>
        <button onClick={downloadPDF} className="px-3 py-1 bg-green-600 rounded">Download Report (PDF)</button>
        <button onClick={onClose} className="ml-2 px-3 py-1 border rounded">Close</button>
      </div>
      {loading && <div>Running analysis…</div>}
      {result && <pre style={{whiteSpace:'pre-wrap'}}>{JSON.stringify(result, null, 2)}</pre>}
    </Modal>
  )
}
