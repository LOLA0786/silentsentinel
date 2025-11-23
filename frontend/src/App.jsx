import React, {useEffect, useState} from "react";
import axios from "axios";
import Tier3Modal from "./components/Tier3Modal";
import StoryboardGraph from "./components/StoryboardGraph";
import AttackPathPanel from "./components/AttackPathPanel";

export default function App(){
  const [incidents,setIncidents] = useState([]);
  const [selected,setSelected] = useState(null);
  const [modalOpen,setModalOpen] = useState(false);

  useEffect(()=>{ fetchAll(); },[]);

  async function fetchAll(){
    const res = await axios.get("http://127.0.0.1:8000/incidents");
    setIncidents(res.data.reverse());
  }

  function openModal(id){
    setSelected(id);
    setModalOpen(true);
  }

  return (
    <div className="p-6">
      <header className="flex justify-between items-center mb-6">
        <h1 className="text-3xl font-extrabold">Silent Sentinel — Dashboard</h1>
        <div>
          <button onClick={()=>{ axios.post('http://127.0.0.1:8000/agent/run'); setTimeout(fetchAll,500) }} className="mr-2 px-4 py-2 bg-indigo-600 rounded">Run Hunt</button>
          <button onClick={fetchAll} className="px-4 py-2 border rounded">Refresh</button>
        </div>
      </header>

      <section className="grid grid-cols-3 gap-4">
        <div className="col-span-2 space-y-3">
          {incidents.map(i=>(
            <div key={i.id} className="p-4 rounded-md bg-slate-700">
              <div className="flex justify-between">
                <div><strong>{i.id}</strong> • {new Date(i.timestamp*1000).toLocaleString()}</div>
                <div>
                  <button onClick={()=>openModal(i.id)} className="px-2 py-1 bg-indigo-500 rounded mr-2">Tier-3</button>
                  <a href={`http://127.0.0.1:8000/incident/${i.id}/report`} className="px-2 py-1 bg-green-600 rounded" target="_blank" rel="noreferrer">PDF</a>
                </div>
              </div>
              <div className="mt-2">{i.description}</div>
            </div>
          ))}
          {incidents.length===0 && <div className="p-6 bg-slate-800 rounded">No incidents yet — click Run Hunt</div>}
        </div>

        <aside className="bg-slate-900 p-4 rounded space-y-4">
          <h2 className="text-xl font-semibold mb-2">Digital Twin</h2>
          <StoryboardGraph incidentId={selected} />
          <AttackPathPanel defaultEntry="endpoint-1" defaultTarget="db-2" />
        </aside>
      </section>

      <Tier3Modal isOpen={modalOpen} onClose={()=>setModalOpen(false)} incidentId={selected} />
    </div>
  )
}
