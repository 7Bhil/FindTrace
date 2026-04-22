import questionary
from rich.console import Console
from rich.tree import Tree
from rich.panel import Panel
from rich.table import Table
from core.models import Entity

console = Console()

class InvestigationUI:
    @staticmethod
    def render_tree(target: str, root: Entity, scam_score: int) -> Tree:
        tree = Tree(f"[bold magenta]{target}[/bold magenta] (Risk: {scam_score}/1000)")
        InvestigationUI._build_tree(root, tree)
        return tree

    @staticmethod
    def render_ip_summary(ips: dict) -> Table:
        """Render a consolidated table of all discovered machine IPs."""
        table = Table(title="Machine Infrastructure Summary", show_header=True, header_style="bold magenta")
        table.add_column("IP Address", style="cyan")
        table.add_column("Source", style="green")
        table.add_column("Location (Geo)", style="yellow")
        table.add_column("Organization (ASN)", style="blue")
        table.add_column("Hostname (PTR)", style="dim")

        for ip, data in ips.items():
            table.add_row(
                ip,
                data.get("source", "Unknown"),
                data.get("geo", "N/A"),
                data.get("asn", "N/A"),
                data.get("ptr", "N/A")
            )
        return table

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
    def render_guide(target_type: str) -> Panel:
        """Provide clear, actionable instructions for beginners based on target type."""
        guide_text = ""
        if target_type == "domain":
            guide_text = (
                "[bold green]OBJECTIF :[/bold green] Identifier l'infrastructure et les machines derrière ce domaine.\n"
                "[bold cyan]Étape 1 :[/bold cyan] Lance un [bold]DNS Scan[/bold] pour trouver les adresses IP.\n"
                "[bold cyan]Étape 2 :[/bold cyan] Utilise [bold]Subdomain Discovery[/bold] pour voir l'étendue de l'infrastructure.\n"
                "[bold cyan]Étape 3 :[/bold cyan] Consulte le [bold]Machine Summary[/bold] pour voir tout ce qui a été trouvé."
            )
        elif target_type == "ip":
            guide_text = (
                "[bold green]OBJECTIF :[/bold green] Caractériser cette machine et son niveau de menace.\n"
                "[bold cyan]Étape 1 :[/bold cyan] Lance un [bold]Port Scan[/bold] pour voir quels services tournent.\n"
                "[bold cyan]Étape 2 :[/bold cyan] Utilise [bold]Shodan[/bold] ou [bold]AbuseIPDB[/bold] pour l'intelligence mondiale.\n"
                "[bold cyan]Étape 3 :[/bold cyan] Vérifie la réputation sur [bold]VirusTotal[/bold]."
            )
        else:
            guide_text = "[bold yellow]Action recommandée :[/bold yellow] Explore les options ci-dessous pour collecter tes premières preuves."

        return Panel(guide_text, title="📖 GUIDE DÉBUTANT - QUE FAIRE MAINTENANT ?", border_style="green")

    @staticmethod
    async def select_action(current_entity: Entity):
        if not current_entity:
            return "exit"

        choices = [
            questionary.Choice(
                "📊 Machine Infrastructure Summary", 
                "summary",
                description="Affiche un tableau complet de toutes les machines et IP découvertes jusqu'ici."
            ),
            questionary.Choice(
                "🎯 Switch Current Target", 
                "switch",
                description="Change de cible pour approfondir l'enquête sur une IP ou un sous-domaine découvert."
            ),
            questionary.Separator(),
        ]
        etype = current_entity.entity_type
        
        if etype == "domain":
            choices += [
                questionary.Choice("DNS Scan", "dns_scan", description="Trouve les IP et les enregistrements DNS (A, MX, TXT) du domaine."),
                questionary.Choice("Web Probe", "web_probe", description="Analyse les technologies web (ThinkPHP, CMS) et les en-têtes HTTP."),
                questionary.Choice("WHOIS Lookup", "whois", description="Récupère les informations sur le propriétaire du domaine."),
                questionary.Choice("Subdomain Discovery", "subdomains", description="Cherche tous les sous-domaines cachés pour cartographier l'infrastructure."),
                questionary.Choice("VirusTotal Check (API)", "virustotal", description="Vérifie la réputation de sécurité mondiale du domaine.")
            ]
        elif etype == "ip":
            choices += [
                questionary.Choice("Port Scan", "port_scan", description="Détecte les ports ouverts et les services actifs sur la machine."),
                questionary.Choice("WHOIS Lookup", "whois", description="Trouve à qui appartient cette plage d'IP."),
                questionary.Choice("Shodan Intelligence (API)", "shodan", description="Interroge Shodan pour voir les vulnérabilités et services exposés."),
                questionary.Choice("AbuseIPDB Check (API)", "abuseip", description="Vérifie si cette IP a été signalée pour des activités malveillantes."),
                questionary.Choice("VirusTotal Check (API)", "virustotal", description="Vérifie si cette IP est connue comme malveillante sur VT.")
            ]
        elif etype == "username":
            choices += [
                questionary.Choice("Maigret Social Search", "maigret_search", description="Traque ce pseudonyme sur des centaines de réseaux sociaux.")
            ]
        elif etype == "email":
            choices += [
                questionary.Choice("Holehe Presence Detection", "holehe_check", description="Vérifie sur quels sites cet email est utilisé pour créer un profil.")
            ]

        choices += [
            questionary.Separator(),
            questionary.Choice("🚪 Exit Investigation", "exit", description="Termine l'enquête et revient au menu principal.")
        ]
        
        return await questionary.select(
            f"Action sur {current_entity.value} ({etype}) :", 
            choices=choices,
            instruction="Utilise les flèches pour choisir et 'Entrée' pour valider."
        ).ask_async()
