import React, {useEffect, useRef} from "react";
import { Network } from "vis-network/peer";

export default function StoryboardGraph({incidentId}){
  const ref = useRef(null);

  useEffect(()=>{
    if(!incidentId) return;
    fetch(`http://127.0.0.1:8000/storyboard/graph/${incidentId}`).then(r=>r.json()).then(data=>{
      if(data.error) return;
      const nodes = data.nodes.map(n=>({id:n.id, label:n.id}));
      const edges = data.edges.map(e=>({from:e.from, to:e.to}));
      const container = ref.current;
      const net = new Network(container, {nodes, edges}, {layout:{hierarchical:false}});
    });
  }, [incidentId]);

  return <div ref={ref} style={{height:400}} />;
}
