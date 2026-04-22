import asyncio
import json
import os
import questionary
from typing import Dict, List, Optional, Any
from rich.panel import Panel
from rich.table import Table
from core.models import Entity
from core.config import SESSIONS_DIR, REPORTS_DIR, MAX_SCORE
from core.validators import sanitize_filename, detect_target_type
from core.scoring import GlobalScoringEngine
from core.ui import InvestigationUI, console

# Tool imports
from tools.dns_checker import get_dns_records
from tools.port_scanner import scan_ports
from tools.web_prober import probe_web
from tools.whois_parser import get_whois_info
from tools.sub_discovery import discover_subdomains

from tools.maigret_wrapper import run_maigret
from tools.holehe_wrapper import run_holehe
from tools.geo_ip import get_ip_geo
from tools.shodan_wrapper import scan_shodan
from tools.virustotal_wrapper import scan_virustotal
from tools.abuseipdb_wrapper import check_abuseip

class InvestigationManager:
    """Universal OSINT orchestrator."""
    def __init__(self, target: str, target_type: str = "domain"):
        self.target = target
        self.root = Entity(target, target_type)
        self.entities: Dict[str, Entity] = {f"{target_type}:{target}": self.root}
        self.current_entity = self.root
        self.scam_score = 0
        self.observations: List[str] = []
        self.discovered_ips: Dict[str, Dict[str, Any]] = {} # Track all unique IPs found
        self._lock = asyncio.Lock()
        self.running = True

        # If starting with an IP, register it
        if target_type == "ip":
            asyncio.create_task(self._register_ip(target, "Root Target"))

    async def _register_ip(self, ip: str, source: str):
        """Internal helper to log a discovered IP."""
        if ip not in self.discovered_ips:
            self.discovered_ips[ip] = {
                "source": source,
                "geo": "Searching...",
                "asn": "Searching...",
                "ptr": "Searching..."
            }
            # Auto-enrich in background
            geo = await get_ip_geo(ip)
            if geo:
                self.discovered_ips[ip].update({
                    "geo": f"{geo.get('country', '??')} ({geo.get('city', '??')})",
                    "asn": geo.get("org", "Unknown"),
                    "ptr": geo.get("hostname", "None")
                })

    async def add_entity(self, value: str, entity_type: str, parent_id: Optional[str] = None) -> Entity:
        async with self._lock:
            eid = f"{entity_type}:{value}"
            if eid not in self.entities:
                self.entities[eid] = Entity(value, entity_type)
            
            entity = self.entities[eid]
            
            # Auto-enrich IP with Geo data
            if entity_type == "ip" and "geo" not in entity.findings:
                geo_data = await get_ip_geo(value)
                if geo_data:
                    entity.add_finding("geo", geo_data, "Geographic Location")

            if parent_id and parent_id in self.entities:
                parent = self.entities[parent_id]
                if entity not in parent.children:
                    parent.children.append(entity)
            return entity

    async def run_tool(self, tool_id: str, entity: Entity):
        console.print(f"\n[bold blue][*] Executing {tool_id} on {entity.value}...[/bold blue]")
        
        async with self._lock:
            if tool_id == "dns_scan":
                res = await get_dns_records(entity.value)
                entity.add_finding("dns", res, "DNS Records")
                ips = res.get('A', [])
                for ip in ips: 
                    await self.add_entity(ip, "ip", f"{entity.entity_type}:{entity.value}")
                    await self._register_ip(ip, f"DNS A-Record for {entity.value}")
                console.print(f"[success][+] Found {len(ips)} IP addresses and {len(res.get('MX', []))} mail servers.[/success]")
            
            elif tool_id == "port_scan":
                res = await scan_ports(entity.value)
                entity.add_finding("ports", res, "Open Ports")
                console.print(f"[success][+] Identified {len(res)} open ports.[/success]")
                
            elif tool_id == "web_probe":
                res = await probe_web(entity.value)
                entity.add_finding("web", res, "Web Services")
                if res.get('techs'):
                    console.print(f"[success][+] Technologies detected: {', '.join(res['techs'])}[/success]")
                
            elif tool_id == "subdomains":
                res = await discover_subdomains(entity.value)
                entity.add_finding("subdomains", res, "Subdomains")
                subs = res.get('subdomains', [])
                for sub in subs: 
                    await self.add_entity(sub, "domain", f"{entity.entity_type}:{entity.value}")
                console.print(f"[success][+] Discovered {len(subs)} subdomains.[/success]")

            elif tool_id in ["shodan", "virustotal", "abuseip"]:
                # API tools
                console.print(f"[info][*] Querying global intelligence for {entity.value}...[/info]")
                # ... existing logic ...

            elif tool_id == "maigret_search":
                res = await run_maigret(entity.value)
                entity.add_finding("maigret", res, "Maigret Username Reconstruction")
                
            elif tool_id == "holehe_check":
                res = await run_holehe(entity.value)
                entity.add_finding("holehe", res, "Email Presence Detection")

            elif tool_id == "shodan":
                res = await scan_shodan(entity.value)
                entity.add_finding("shodan", res, "Shodan IP Intelligence")

            elif tool_id == "virustotal":
                res = await scan_virustotal(entity.value)
                entity.add_finding("virustotal", res, "VirusTotal Reputation")

            elif tool_id == "abuseip":
                res = await check_abuseip(entity.value)
                entity.add_finding("abuseip", res, "AbuseIPDB Reputation")

        # Calculate Global Risk Score (0-1000)
        all_findings = " ".join([json.dumps(f.data) for e in self.entities.values() for f in e.findings.values()])
        self.scam_score, self.observations = GlobalScoringEngine.calculate_risk(all_findings)

    async def interactive_loop(self):
        while self.running:
            if not self.current_entity:
                self.current_entity = self.root

            console.clear()
            # Show guidance for beginners
            guide = InvestigationUI.render_guide(self.current_entity.entity_type)
            console.print(guide)
            
            tree = InvestigationUI.render_tree(self.target, self.root, self.scam_score)
            console.print(Panel(tree, title=f"FindTrace 2.0 - Active Investigation: {self.target}"))
            
            choice = await InvestigationUI.select_action(self.current_entity)
            
            if not choice or choice == "exit":
                self.running = False
            elif choice == "switch":
                switch_choices = [questionary.Choice(f"{e.entity_type.upper()}: {e.value}", e) for e in self.entities.values()]
                new_entity = await questionary.select("Switch to which target?", choices=switch_choices).ask_async()
                if new_entity:
                    self.current_entity = new_entity
            elif choice == "summary":
                summary_table = InvestigationUI.render_ip_summary(self.discovered_ips)
                console.print(summary_table)
                await questionary.press_any_key_to_continue().ask_async()
            else:
                await self.run_tool(choice, self.current_entity)
                await questionary.press_any_key_to_continue().ask_async()

    def save_session(self):
        def entity_to_dict(e: Entity):
            return {
                "value": e.value,
                "type": e.entity_type,
                "findings": {tid: {"data": f.data, "desc": f.description} for tid, f in e.findings.items()},
                "children": [entity_to_dict(c) for c in e.children]
            }
        
        data = {"target": self.target, "tree": entity_to_dict(self.root)}
        path = os.path.join(SESSIONS_DIR, f"{sanitize_filename(self.target)}.json")
        os.makedirs(SESSIONS_DIR, exist_ok=True)
        with open(path, 'w') as f: json.dump(data, f, indent=4)
        return path

    def _get_all_findings_text(self) -> str:
        """Helper to aggregate all findings into a single string for scoring."""
        return " ".join([json.dumps(f.data) for e in self.entities.values() for f in e.findings.values()])

    def export_report(self):
        results = {eid: {"type": e.entity_type, "value": e.value, "findings": {tid: f.data for tid, f in e.findings.items()}} 
                   for eid, e in self.entities.items()}
        path = os.path.join(REPORTS_DIR, f"{sanitize_filename(self.target)}_report.json")
        os.makedirs(REPORTS_DIR, exist_ok=True)
        with open(path, 'w') as f: json.dump(results, f, indent=4)
        return path
