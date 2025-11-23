import React, {useState} from "react";
import axios from "axios";

export default function AttackPathPanel({defaultEntry, defaultTarget}){
  const [entry,setEntry] = useState(defaultEntry||"endpoint-1");
  const [target,setTarget] = useState(defaultTarget||"db-2");
  const [query,setQuery] = useState("data exfil");
  const [result,setResult] = useState(null);

  async function runSim(){
    const res = await axios.post(`http://127.0.0.1:8000/attackpath/simulate`, { entry_nodes:[entry], targets:[target], query });
    setResult(res.data);
  }

  return (
    <div className="p-3 bg-slate-800 rounded">
      <h3 className="font-bold mb-2">Attack Path Simulator</h3>
      <div className="mb-2">
        <label>Entry node: <input value={entry} onChange={e=>setEntry(e.target.value)} className="ml-2 p-1 rounded bg-black text-white"/></label>
      </div>
      <div className="mb-2">
        <label>Target node: <input value={target} onChange={e=>setTarget(e.target.value)} className="ml-2 p-1 rounded bg-black text-white"/></label>
      </div>
      <div className="mb-2">
        <label>Query (vector hints): <input value={query} onChange={e=>setQuery(e.target.value)} className="ml-2 p-1 rounded bg-black text-white" /></label>
      </div>
      <div>
        <button onClick={runSim} className="px-3 py-1 bg-amber-600 rounded">Simulate</button>
      </div>
      {result && <pre className="mt-2 text-sm">{JSON.stringify(result, null, 2)}</pre>}
    </div>
  )
}
