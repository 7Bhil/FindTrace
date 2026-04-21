import questionary
from rich.console import Console
from rich.tree import Tree
from rich.panel import Panel
from core.models import Entity

console = Console()

class InvestigationUI:
    @staticmethod
    def render_tree(target: str, root: Entity, scam_score: int) -> Tree:
        tree = Tree(f"[bold magenta]{target}[/bold magenta] (Risk: {scam_score}/1000)")
        InvestigationUI._build_tree(root, tree)
        return tree

    @staticmethod
    def _build_tree(entity: Entity, node):
        loc = ""
        if "geo" in entity.findings:
            geo = entity.findings["geo"].data
            loc = f" [{geo.get('countryCode', '??')}]"
            
        label = f"[cyan]{entity.entity_type.upper()}{loc}:[/cyan] {entity.value}"
        if entity.findings:
            label += f" [yellow]({len(entity.findings)} findings)[/yellow]"
        
        sub_node = node.add(label)
        for child in entity.children:
            InvestigationUI._build_tree(child, sub_node)

    @staticmethod
    async def select_action(current_entity: Entity):
        choices = []
        etype = current_entity.entity_type
        
        if etype == "domain":
            choices += [
                questionary.Choice(f"DNS Scan", "dns_scan"),
                questionary.Choice(f"Web Probe", "web_probe"),
                questionary.Choice(f"WHOIS Lookup", "whois"),
                questionary.Choice(f"Subdomain Discovery", "subdomains")
            ]
        elif etype == "ip":
            choices += [
                questionary.Choice(f"Port Scan", "port_scan"),
                questionary.Choice(f"WHOIS Lookup", "whois")
            ]
        elif etype == "username":
            choices += [
                questionary.Choice(f"Maigret Username Search", "maigret_search")
            ]
        elif etype == "email":
            choices += [
                questionary.Choice(f"Holehe Email Presence", "holehe_check")
            ]

        choices += [
            questionary.Separator(),
            questionary.Choice("Switch Entity", "switch"),
            questionary.Choice("Generate Report & Exit", "exit")
        ]
        return await questionary.select(f"Action on {current_entity.value} ({etype}):", choices=choices).ask_async()
