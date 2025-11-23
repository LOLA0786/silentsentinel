import json, threading, time, random
from typing import List, Dict

class ZeroDayGuardian:
    """
    PoC Zero-Day Guardian:
    - Loads a local CVE feed (agents/zero_day/cve_feed.json)
    - Scans the Engine.graph (InfraGraph) for nodes exposing packages
    - Creates incidents via engine.manual_incident for findings
    - Runs periodically on a background thread
    """

    def __init__(self, engine, poll_interval: int = 60):
        self.engine = engine
        self.poll_interval = poll_interval
        self._running = True
        self._load_feed()
        # start background scanner thread
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _load_feed(self):
        try:
            with open("agents/zero_day/cve_feed.json", "r") as f:
                self.feed = json.load(f)
        except FileNotFoundError:
            self.feed = []
        # normalize feed entries
        for e in self.feed:
            e.setdefault("cvss", 5.0)

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running:
            try:
                self.scan_and_report()
            except Exception:
                pass
            time.sleep(self.poll_interval)

    def _node_packages(self) -> Dict[str, List[Dict]]:
        """
        Return a mapping node_id -> list of installed packages (simulated).
        For demo we create packages if absent on nodes.
        """
        g = self.engine.graph.G
        node_pkgs = {}
        for n, meta in g.nodes(data=True):
            # skip incident nodes (they will be of type 'incident')
            ntype = meta.get("type")
            if ntype == "incident":
                continue
            # if node has packages metadata, use it, otherwise simulate a few
            pkgs = meta.get("packages")
            if not pkgs:
                # simulate realistic packages with versions (demo only)
                pkgs = [
                    {"name": "openssl", "version": random.choice(["1.1.1","1.1.0","1.2.0"])},
                    {"name": "log4j", "version": random.choice(["2.14.1","2.13.0","2.16.0"])},
                    {"name": "nginx", "version": random.choice(["1.18.0","1.20.1","1.19.0"])}
                ]
                # store simulated packages back to graph node so future scans see them
                g.nodes[n]["packages"] = pkgs
            node_pkgs[n] = pkgs
        return node_pkgs

    def _version_vulnerable(self, installed: str, vulnerable_spec: str) -> bool:
        """
        Very simple semver comparison for PoC.
        Supports only '<=' spec like '<=1.1.1'.
        This is a simulation — do NOT use for real vulnerability gating.
        """
        try:
            if vulnerable_spec.startswith("<="):
                spec_v = vulnerable_spec[2:].strip()
                # compare by splitting numbers
                iv = [int(x) for x in installed.split(".") if x.isdigit()]
                sv = [int(x) for x in spec_v.split(".") if x.isdigit()]
                # pad
                while len(iv) < len(sv): iv.append(0)
                while len(sv) < len(iv): sv.append(0)
                return tuple(iv) <= tuple(sv)
        except Exception:
            return False
        return False

    def scan_once(self) -> List[Dict]:
        """
        Scans current graph for exposures and returns findings list.
        Each finding is a dict with keys: cve_id, node, package, installed_version, cvss.
        """
        findings = []
        node_pkgs = self._node_packages()
        for cve in self.feed:
            pkg = cve.get("package")
            vuln_spec = cve.get("vulnerable_versions", "")
            for node, pkgs in node_pkgs.items():
                for p in pkgs:
                    if p.get("name") == pkg:
                        installed = p.get("version", "0.0.0")
                        if self._version_vulnerable(installed, vuln_spec):
                            findings.append({
                                "cve_id": cve["cve_id"],
                                "node": node,
                                "package": pkg,
                                "installed_version": installed,
                                "cvss": cve.get("cvss", 5.0),
                                "description": cve.get("description", "")
                            })
        return findings

    def scan_and_report(self):
        findings = self.scan_once()
        for f in findings:
            # derive severity from CVSS (map 0-10 to 0-0.999)
            severity = min(0.999, round((f["cvss"] / 10.0) * 0.99, 3))
            desc = f'Zero-Day Exposure: {f["cve_id"]} on {f["node"]} ({f["package"]} {f["installed_version"]}) - {f["description"]}'
            # create incident in engine (safe, simulated)
            self.engine.manual_incident(f["node"], severity, desc)
        return findings

    def shutdown(self):
        self.stop()
        if self.thread.is_alive():
            self.thread.join(timeout=1)
