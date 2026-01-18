from rich.prompt import Prompt
from rich.console import Console
from rich.panel import Panel
import datetime

console = Console()

def ask_approval(command: str, purpose: str, risk_level: str = "medium", needs_root: bool = False) -> bool:
    """
    Komut çalıştırmadan önce kullanıcıdan onay al
    
    Args:
        command: Çalıştırılacak komut
        purpose: Komutun amacı
        risk_level: Tehlike seviyesi (low, medium, high, critical)
        needs_root: Root yetkisi gerekli mi?
    
    Returns:
        True: Onay verildi
        False: İptal edildi
    """
    
    # Risk rengi
    risk_colors = {
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "red"
    }
    color = risk_colors.get(risk_level, "yellow")
    
    # Onay paneli
    panel_text = f"""
[bold cyan]🔧 Komut Onayı[/bold cyan]

[bold]Komut:[/bold]
[{color}]{command}[/{color}]

[bold]Amaç:[/bold]
{purpose}

[bold]Tehlike Seviyesi:[/bold] [{color}]{risk_level.upper()}[/{color}]
"""
    
    if needs_root:
        panel_text += "\n[bold red]⚠️  ROOT YETKİSİ GEREKLİ[/bold red]"
    
    panel_text += f"\n[dim]Zaman: {datetime.datetime.now().strftime('%H:%M:%S')}[/dim]"
    
    console.print(Panel(panel_text, title="DRAKBEN", border_style="cyan"))
    
    # Onay sor
    choice = Prompt.ask(
        "\n[bold]Bunu uygulamak istiyor musun?[/bold]",
        choices=["y", "e", "yes", "evet", "n", "no", "hayır"],
        default="n"
    ).lower()
    
    # Sonuç
    if choice in ["y", "e", "yes", "evet"]:
        console.print("\n[green]✅ Onay verildi. Komut çalıştırılıyor...[/green]\n")
        return True
    else:
        console.print("\n[red]❌ Komut iptal edildi.[/red]\n")
        return False


def ask_exploit_confirmation(cve: str, target: str, exploit_type: str) -> bool:
    """Exploit uygulamadan önce onay al"""
    
    console.print(Panel(f"""
[bold cyan]🎯 EXPLOIT ONAYLANDIRMASI[/bold cyan]

[bold]CVE:[/bold] [red]{cve}[/red]
[bold]Hedef:[/bold] [yellow]{target}[/yellow]
[bold]Exploit Türü:[/bold] [red]{exploit_type}[/red]

[bold]⚠️  UYARI: Bu zafiyet, hedef sistemde hasara neden olabilir![/bold]
[dim]Sadece yetkili testlerde kullanın.[/dim]
""", title="DRAKBEN", border_style="red"))
    
    choice = Prompt.ask(
        "[bold]Devam etmek istiyor musun?[/bold]",
        choices=["y", "e", "n"],
        default="n"
    ).lower()
    
    return choice in ["y", "e"]


def ask_payload_delivery(payload_type: str, delivery_method: str, target: str) -> bool:
    """Payload gönderiminden önce onay al"""
    
    console.print(Panel(f"""
[bold cyan]💣 PAYLOAD GÖNDERIMI ONAYLANDIRMASI[/bold cyan]

[bold]Payload Türü:[/bold] [magenta]{payload_type}[/magenta]
[bold]Gönderim Yöntemi:[/bold] [yellow]{delivery_method}[/yellow]
[bold]Hedef:[/bold] [red]{target}[/red]

[bold]⚠️  UYARI: Payload'ı gönderdikten sonra geri alınamaz![/bold]
""", title="DRAKBEN", border_style="magenta"))
    
    choice = Prompt.ask(
        "[bold]Devam etmek istiyor musun?[/bold]",
        choices=["y", "e", "n"],
        default="n"
    ).lower()
    
    return choice in ["y", "e"]
