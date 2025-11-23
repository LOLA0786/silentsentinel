import time
from typing import Dict, List

class Tier2Analyst:
    """
    AI Tier-2 Analyst (PoC, offline-safe)
    - Takes an incident object
    - Generates:
        - executive summary
        - analyst-level explanation
        - root cause hypothesis
        - recommended actions
    """

    def analyze(self, incident: Dict, related: List[Dict]):
        src = incident["source"]
        severity = incident["severity"]
        desc = incident["description"]

        # pattern recognition heuristics
        if "brute" in desc.lower():
            attack_type = "Credential Brute Force"
            risk = "High probability of account compromise"
            action = [
                "Enforce MFA immediately",
                "Lock or throttle offending source IP",
                "Rotate exposed credentials",
                "Review authentication logs for lateral movement"
            ]
        elif "exfil" in desc.lower():
            attack_type = "Possible Data Exfiltration"
            risk = "High risk of sensitive data leakage"
            action = [
                "Disable egress temporarily",
                "Inspect outbound traffic for large transfers",
                "Audit S3 buckets / GCS storage for strange reads",
                "Rotate access tokens tied to the node"
            ]
        elif "kube" in desc.lower():
            attack_type = "Suspicious Kubernetes Pod Exec"
            risk = "Possible container breakout or cluster compromise"
            action = [
                "Isolate pod",
                "Check RBAC bindings",
                "Review API server audit logs",
                "Scan container image for known threats"
            ]
        else:
            attack_type = "General Security Anomaly"
            risk = "Requires further investigation"
            action = [
                "Check system logs",
                "Review IAM permissions",
                "Validate recent configuration changes",
            ]

        # correlate other incidents from same source
        correlated = [i for i in related if i["source"] == src and i["id"] != incident["id"]]
        correlation_summary = (
            f"{len(correlated)} related events detected from {src}" 
            if correlated else 
            "No correlated events detected."
        )

        analysis = {
            "timestamp": time.time(),
            "incident_id": incident["id"],
            "executive_summary": f"Potential {attack_type} detected on {src}. Severity {severity}.",
            "attack_type": attack_type,
            "why_it_matters": risk,
            "description_analysis": f"The system observed: {desc}. "
                                    f"This behavior aligns with {attack_type} patterns.",
            "correlation": correlation_summary,
            "recommended_actions": action,
        }

        return analysis
