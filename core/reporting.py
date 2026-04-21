from typing import List, Dict
from core.models import Entity

def generate_abuse_report(root_entity: Entity, scam_score: int, observations: List[str]) -> str:
    """
    Modernized reporting engine using the V5 Entity model.
    """
    report = f"""
SUBJECT: OSINT Investigation Report for {root_entity.value}
RISK SCORE: {scam_score}/100

FindTrace V5 has identified this infrastructure as matching high-risk patterns.

INVESTIGATION SUMMARY:
- Root Target: {root_entity.value} ({root_entity.entity_type})
- Detected Threats: {len(observations)}

CRITICAL OBSERVATIONS:
"""
    for obs in observations:
        report += f"  [!] {obs}\n"
        
    report += "\nDETAILED DISCOVERY TREE:\n"
    
    def walk_tree(entity: Entity, indent: int = 0):
        lines = [f"{'  ' * indent}- {entity.value} ({entity.entity_type})"]
        for child in entity.children:
            lines.append(walk_tree(child, indent + 1))
        return "\n".join(lines)

    report += walk_tree(root_entity)
    
    report += """
\nBest regards,
FindTrace V5 Automated Investigative Engine
"""
    return report
