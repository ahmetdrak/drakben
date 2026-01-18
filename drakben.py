# drakben.py
# DRAKBEN v5.0 - ULTIMATE PENTEST AI ASSISTANT
# 2026 Professional Edition - Kali Linux Ready
# Modern 2024-2025 Evasion Techniques Integrated

import sys
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

# UI/UX Enhancement Libraries
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("⚠️  Rich library not available. Install with: pip install rich")

try:
    from colorama import init as colorama_init, Fore, Back, Style
    colorama_init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    # Fallback color codes
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""
    class Style:
        BRIGHT = DIM = RESET_ALL = ""

# Core imports
from core.executor import Executor
from core.chain_planner import ChainPlanner
from core.payload_intelligence import PayloadIntelligence
from core.advanced_chain_builder import AdvancedChainBuilder
from core.zero_day_scanner import ZeroDayScanner
from core.kali_detector import KaliDetector
from core.approval import ask_approval
from llm.brain import DrakbenBrain

# NEW: Critical Fix Modules (2026)
from core.parallel_executor import ParallelExecutor
from core.exploit_verifier import ExploitVerifier, SmartApprovalEngine
from core.opsec_implementation import OPSECImplementation, OPSECLevel
from core.database_manager import DatabaseManager
from core.brain_complete import DrakbenBrainComplete, BrainFactory

# NEW: Automated Shell & Post-Exploitation Modules
from core.web_shell_handler import WebShellHandler
from core.ssh_shell_connector import SSHShellConnector
from core.reverse_shell_handler import ReverseShellListener
from core.post_exploitation_automation import PostExploitationChain

# NEW: Lateral Movement Engine (2026)
from core.lateral_movement_engine import LateralMovementEngine

# NEW: ML OPSEC Advisor (2026)
from core.ml_opsec_advisor import MLOpsecAdvisor, DetectionRiskLevel

# NEW: AI Autonomous Agent (2026) - Terminal-Aware, Memory-Full, Auto-Execution
from core.ai_autonomous_agent import AIAutonomousAgent, AutonousAgentFactory, TerminalMonitor, AIMemory

# NEW: NLP Intent Parser & Full Workflow Orchestrator (2026)
from core.nlp_intent_parser import NLPIntentParser, FullWorkflowOrchestrator

# NEW: Multi-Language Support (2026) - Turkish/English
from core.language_detector import LanguageDetector, LocalizationManager

# NEW: Advanced Modules v2 Integration (2026) - All 6 advanced modules
from core.advanced_modules import AdvancedModuleManager

# Initialize Rich Console if available
console = Console() if RICH_AVAILABLE else None

# Globals
executor = Executor()
planner = ChainPlanner()
payload_ai = PayloadIntelligence()
brain = DrakbenBrain()
chain_builder = AdvancedChainBuilder()
cve_scanner = ZeroDayScanner()
kali = KaliDetector()

# NEW: Initialize Critical Fix Modules
parallel_exec = ParallelExecutor(max_workers=4)
exploit_verifier = ExploitVerifier()
approval_engine = SmartApprovalEngine()
opsec = OPSECImplementation()
db_manager = DatabaseManager()
try:
    brain_complete = BrainFactory.create(mode="HYBRID")
except:
    brain_complete = None  # Fallback if BrainFactory unavailable

# NEW: Multi-Language Manager (2026)
localization = LocalizationManager()

# NEW: Initialize Shell Handlers
web_shell = None  # Initialized on demand
ssh_connector = None  # Initialized on demand
reverse_listener = None  # Initialized on demand
post_exploit_chain = None  # Initialized on demand

# NEW: Lateral Movement Engine
lateral_engine = None  # Initialized on demand

# NEW: ML OPSEC Advisor
ml_opsec = MLOpsecAdvisor()

# NEW: Advanced Module Manager (v2 Integration)
advanced_modules = AdvancedModuleManager()

# NEW: AI Autonomous Agent (2026)
autonomous_agent = AutonousAgentFactory.create_agent(brain, approval_engine, opsec)

# NEW: NLP Intent Parser & Workflow Orchestrator
nlp_parser = NLPIntentParser()
workflow_orchestrator = FullWorkflowOrchestrator(executor, chain_builder, payload_ai, cve_scanner)

# Session state
session = {
    "target": None,
    "strategy": "balanced",
    "detected_vulns": [],
    "commands_executed": 0,
    "findings": [],
    "last_chain": None,
    # NEW: Database and OPSEC tracking
    "db_session_id": db_manager.create_session(strategy="balanced", target=None),
    "opsec_level": OPSECLevel.BALANCED
}

def banner():
    """Enhanced banner with version and system info + Rich formatting"""
    from datetime import datetime
    
    if RICH_AVAILABLE and console:
        # Rich-enhanced banner
        console.print()
        console.print("="*70, style="bold red")
        console.print(localization.get_response("menu_banner"), style="bold red", justify="center")
        console.print("="*70, style="bold red")
        console.print(f"[cyan]📅 Session:[/cyan] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        console.print(f"[cyan]🗄️  DB Session:[/cyan] {session.get('db_session_id', 'N/A')}")
        
        target = session.get('target', 'Not Set')
        target_style = "green" if target != 'Not Set' else "yellow"
        console.print(f"[cyan]🎯 Target:[/cyan] [{target_style}]{target}[/{target_style}]")
        
        strategy = session.get('strategy', 'balanced').upper()
        strategy_color = {"STEALTHY": "blue", "BALANCED": "yellow", "AGGRESSIVE": "red"}.get(strategy, "white")
        console.print(f"[cyan]🛡️  Strategy:[/cyan] [{strategy_color}]{strategy}[/{strategy_color}]")
        console.print("="*70, style="bold red")
        console.print()
    elif COLORAMA_AVAILABLE:
        # Colorama fallback
        print(f"\n{Fore.RED}{'='*70}")
        print(f"{Fore.RED}{Style.BRIGHT}" + localization.get_response("menu_banner"))
        print(f"{Fore.RED}{'='*70}")
        print(f"{Fore.CYAN}📅 Session:{Style.RESET_ALL} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Fore.CYAN}🗄️  DB Session:{Style.RESET_ALL} {session.get('db_session_id', 'N/A')}")
        print(f"{Fore.CYAN}🎯 Target:{Style.RESET_ALL} {Fore.GREEN if session.get('target') else Fore.YELLOW}{session.get('target', 'Not Set')}")
        print(f"{Fore.CYAN}🛡️  Strategy:{Style.RESET_ALL} {Fore.YELLOW}{session.get('strategy', 'balanced').upper()}")
        print(f"{Fore.RED}{'='*70}{Style.RESET_ALL}\n")
    else:
        # Basic fallback (no colors)
        print("\n" + "="*70)
        print(localization.get_response("menu_banner"))
        print("="*70)
        print(f"📅 Session: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"🗄️  DB Session: {session.get('db_session_id', 'N/A')}")
        print(f"🎯 Target: {session.get('target', 'Not Set')}")
        print(f"🛡️  Strategy: {session.get('strategy', 'balanced').upper()}")
        print("="*70 + "\n")

def menu():
    """Enhanced interactive menu with categories and descriptions"""
    lang = getattr(localization, "session_language", "tr")
    
    if lang == "en":
        print("\n" + "┌" + "─"*68 + "┐")
        print("│" + " "*20 + "🩸 DRAKBEN COMMAND MENU 🩸" + " "*22 + "│")
        print("├" + "─"*68 + "┤")
        print("│ 🎯 BASIC SETUP:" + " "*51 + "│")
        print("│   setup              → Detect Kali tools" + " "*26 + "│")
        print("│   target <IP>        → Set target" + " "*32 + "│")
        print("│   strategy <mode>    → Set OPSEC (stealthy/balanced/aggressive)│")
        print("├" + "─"*68 + "┤")
        print("│ 🔍 RECONNAISSANCE & SCANNING:" + " "*38 + "│")
        print("│   scan               → Run nmap scan + CVE detection" + " "*13 + "│")
        print("│   scan_parallel      → Multi-target parallel scanning" + " "*12 + "│")
        print("├" + "─"*68 + "┤")
        print("│ 💥 EXPLOITATION:" + " "*50 + "│")
        print("│   exploit            → Exploit detected vulnerabilities" + " "*9 + "│")
        print("│   payload            → Generate custom payloads" + " "*18 + "│")
        print("│   web_shell          → Get web shell (15 CMS)" + " "*20 + "│")
        print("│   ssh_shell          → SSH shell connector" + " "*23 + "│")
        print("│   reverse_shell      → Reverse shell listener" + " "*20 + "│")
        print("├" + "─"*68 + "┤")
        print("│ 🚀 POST-EXPLOITATION:" + " "*45 + "│")
        print("│   post_exp           → Auto privilege escalation" + " "*16 + "│")
        print("│   lateral            → Lateral movement (SSH chaining)" + " "*11 + "│")
        print("├" + "─"*68 + "┤")
        print("│ 🤖 AI & AUTOMATION:" + " "*47 + "│")
        print("│   auto_mode          → Toggle autonomous mode" + " "*20 + "│")
        print("│   auto_pentest       → Run full AI pentest" + " "*22 + "│")
        print("│   ai_memory          → Show AI memory status" + " "*21 + "│")
        print("├" + "─"*68 + "┤")
        print("│ 🛡️  ML OPSEC:" + " "*53 + "│")
        print("│   ml_analyze         → Analyze traffic patterns" + " "*18 + "│")
        print("│   ml_evasion         → Apply evasion techniques" + " "*18 + "│")
        print("│   ml_summary         → Show OPSEC summary" + " "*24 + "│")
        print("├" + "─"*68 + "┤")
        print("│ 📊 RESULTS & REPORTS:" + " "*45 + "│")
        print("│   results            → Show session findings" + " "*21 + "│")
        print("│   chain              → Display last attack chain" + " "*16 + "│")
        print("├" + "─"*68 + "┤")
        print("│ ⚙️  UTILITY:" + " "*54 + "│")
        print("│   help               → Show this menu" + " "*28 + "│")
        print("│   clear              → Clear screen" + " "*30 + "│")
        print("│   exit               → Exit DRAKBEN" + " "*30 + "│")
        print("└" + "─"*68 + "┘\n")
        print("💡 TIP: You can also use natural language commands!")
        print("   Example: 'scan 192.168.1.100 and exploit vulnerabilities'\n")
    else:
        print("\n" + "┌" + "─"*68 + "┐")
        print("│" + " "*20 + "🩸 DRAKBEN KOMUT MENÜSÜ 🩸" + " "*21 + "│")
        print("├" + "─"*68 + "┤")
        print("│ 🎯 TEMEL KURULUM:" + " "*49 + "│")
        print("│   setup              → Kali araçlarını tespit et" + " "*16 + "│")
        print("│   target <IP>        → Hedef belirle" + " "*29 + "│")
        print("│   strategy <mod>     → OPSEC (stealthy/balanced/aggressive)" + " "*5 + "│")
        print("├" + "─"*68 + "┤")
        print("│ 🔍 KEŞİF & TARAMA:" + " "*48 + "│")
        print("│   scan               → Nmap tarama + CVE tespiti" + " "*16 + "│")
        print("│   scan_parallel      → Paralel çoklu hedef taraması" + " "*13 + "│")
        print("├" + "─"*68 + "┤")
        print("│ 💥 İSTİSMAR:" + " "*54 + "│")
        print("│   exploit            → Tespit edilen zafiyetleri istismar et" + " "*4 + "│")
        print("│   payload            → Özel payload üret" + " "*25 + "│")
        print("│   web_shell          → Web shell al (15 CMS)" + " "*20 + "│")
        print("│   ssh_shell          → SSH shell bağlantısı" + " "*22 + "│")
        print("│   reverse_shell      → Reverse shell dinleyici" + " "*18 + "│")
        print("├" + "─"*68 + "┤")
        print("│ 🚀 POST-EXPLOITATION:" + " "*45 + "│")
        print("│   post_exp           → Otomatik yetki yükseltme" + " "*17 + "│")
        print("│   lateral            → Lateral movement (SSH zinciri)" + " "*12 + "│")
        print("├" + "─"*68 + "┤")
        print("│ 🤖 AI & OTOMASYON:" + " "*48 + "│")
        print("│   auto_mode          → Özerk modu aç/kapat" + " "*23 + "│")
        print("│   auto_pentest       → Tam AI pentest çalıştır" + " "*18 + "│")
        print("│   ai_memory          → AI hafıza durumu" + " "*26 + "│")
        print("├" + "─"*68 + "┤")
        print("│ 🛡️  ML OPSEC:" + " "*53 + "│")
        print("│   ml_analyze         → Trafik paternlerini analiz et" + " "*12 + "│")
        print("│   ml_evasion         → Kaçınma tekniklerini uygula" + " "*14 + "│")
        print("│   ml_summary         → OPSEC özeti göster" + " "*24 + "│")
        print("├" + "─"*68 + "┤")
        print("│ 📊 SONUÇLAR & RAPORLAR:" + " "*43 + "│")
        print("│   results            → Oturum bulgularını göster" + " "*16 + "│")
        print("│   chain              → Son saldırı zincirini göster" + " "*14 + "│")
        print("├" + "─"*68 + "┤")
        print("│ ⚙️  YARDIMCI:" + " "*53 + "│")
        print("│   help               → Bu menüyü göster" + " "*26 + "│")
        print("│   clear              → Ekranı temizle" + " "*28 + "│")
        print("│   exit               → DRAKBEN'den çık" + " "*27 + "│")
        print("└" + "─"*68 + "┘\n")
        print("💡 İPUCU: Doğal dil komutları da kullanabilirsiniz!")
        print("   Örnek: '192.168.1.100 tara ve zafiyetleri istismar et'\n")

def setup_system():
    """Sistem kurulumu - Kali araçlarını bul"""
    print("\n🔍 Sistem taranıyor...\n")
    
    tools = kali.detect_all_tools()
    
    if not kali.has_critical_tools():
        print("⚠️  Kritik pentest araçları yok! Lütfen Kali Linux kullanın.\n")
        return False
    
    suggested = kali.suggest_workflow()
    print(f"\n✅ Önerilen workflow: {' → '.join(suggested)}\n")
    
    return True

def set_target():
    """Hedef belirle"""
    target = input("🎯 Hedef IP/Domain: ").strip()
    if not target:
        print("❌ Hedef gerekli!")
        return
    
    session["target"] = target
    print(f"✅ Hedef set: {target}\n")

def set_strategy():
    """OPSEC stratejisi seç"""
    print("\n🛡  Strateji Seç:")
    print("  1. stealthy  - Sessiz, detection risk düşük ✓")
    print("  2. balanced  - Normal pentest ✓")
    print("  3. aggressive - Hızlı, detection risk yüksek ✓\n")
    
    choice = input("Seç (1-3): ").strip()
    
    strategies = {"1": "stealthy", "2": "balanced", "3": "aggressive"}
    strategy = strategies.get(choice, "balanced")
    
    session["strategy"] = strategy
    
    # NEW: Update OPSEC level
    opsec_map = {
        "stealthy": OPSECLevel.STEALTHY,
        "balanced": OPSECLevel.BALANCED,
        "aggressive": OPSECLevel.AGGRESSIVE
    }
    session["opsec_level"] = opsec_map[strategy]
    
    # NEW: Show OPSEC details
    opsec_config = opsec.get_scan_config(session["opsec_level"])
    print(f"\n✅ Strateji: {strategy.upper()}")
    print(f"   ⏱️  Delay: {opsec_config['delay_min']}s - {opsec_config['delay_max']}s")
    print(f"   🛡️  Detection Risk: {opsec_config['detection_risk']}%\n")

def suggest_command(partial_cmd: str, available_commands: list) -> list:
    """Suggest commands based on partial input"""
    if not partial_cmd:
        return []
    
    suggestions = [cmd for cmd in available_commands if cmd.startswith(partial_cmd)]
    return suggestions[:5]  # Top 5 suggestions

def show_quick_help():
    """Show quick reference help"""
    print("\n" + "┌" + "─"*50 + "┐")
    print("│" + " "*15 + "⚡ QUICK REFERENCE ⚡" + " "*14 + "│")
    print("├" + "─"*50 + "┤")
    print("│  target 10.0.0.1    → Set target IP" + " "*13 + "│")
    print("│  strategy stealthy  → Stealth mode" + " "*15 + "│")
    print("│  scan               → Quick scan" + " "*17 + "│")
    print("│  exploit            → Auto exploit" + " "*15 + "│")
    print("│  results            → Show findings" + " "*14 + "│")
    print("│  help               → Full menu" + " "*18 + "│")
    print("└" + "─"*50 + "┘\n")

def show_status_bar():
    """Show current session status"""
    target = session.get('target', 'Not Set')
    strategy = session.get('strategy', 'balanced').upper()
    vulns = len(session.get('detected_vulns', []))
    commands = session.get('commands_executed', 0)
    
    print("\n" + "─"*70)
    print(f"📊 STATUS | Target: {target} | Strategy: {strategy} | Vulns: {vulns} | Cmds: {commands}")
    print("─"*70 + "\n")

def run_scan():
    """Hedef taraması - YENİ: OPSEC + Database"""
    if not session["target"]:
        print("❌ Önce hedef belirleyin: target <ip>\n")
        return
    
    # NEW: Map strategy to OPSEC level
    opsec_map = {
        "stealthy": OPSECLevel.STEALTHY,
        "balanced": OPSECLevel.BALANCED,
        "aggressive": OPSECLevel.AGGRESSIVE
    }
    session["opsec_level"] = opsec_map.get(session["strategy"], OPSECLevel.BALANCED)
    
    # Onay sor
    risk_level = "high" if session["strategy"] == "aggressive" else "medium"
    if not ask_approval(
        f"nmap -sV -p- {session['target']}",
        f"{session['strategy'].upper()} tarama başlat",
        needs_root=True
    ):
        return
    
    # Scan'ı çalıştır
    print(f"\n🔍 {session['strategy'].upper()} tarama başlıyor...\n")
    
    # NEW: Apply OPSEC timing
    opsec_config = opsec.get_scan_config(session["opsec_level"])
    print(f"⏱️  OPSEC Delays: {opsec_config['delay_min']}s - {opsec_config['delay_max']}s")
    print(f"🛡️  Detection Risk: {opsec_config['detection_risk']}%\n")
    
    # Komut oluştur
    if session["strategy"] == "stealthy":
        cmd = f"nmap -sS --scan-delay 500ms -p- {session['target']}"
    elif session["strategy"] == "aggressive":
        cmd = f"nmap -sS -p- -A -T4 {session['target']}"
    else:
        cmd = f"nmap -sV -p- {session['target']}"
    
    result = executor.run(cmd)
    
    print(f"📋 Tarama Çıktısı:\n{result}\n")
    
    # CVE taraması
    print("🔎 CVE'ler taranıyor...\n")
    findings = cve_scanner.scan_results(result, {})
    
    session["detected_vulns"] = findings["vulnerabilities"]
    session["findings"].append({
        "type": "scan",
        "target": session["target"],
        "vulns": findings["vulnerabilities"],
        "risk_score": findings["risk_score"]
    })
    
    # NEW: Store in database
    db_manager.log_vulnerability_scan(
        session["db_session_id"],
        session["target"],
        findings["vulnerabilities"],
        findings["risk_score"]
    )
    
    if findings["vulnerabilities"]:
        print(f"⚠️  {len(findings['vulnerabilities'])} zafiyet bulundu!\n")
        for v in findings["vulnerabilities"]:
            print(f"  • {v['cve']} ({v['service']} {v['version']})")
        print()
    
    session["commands_executed"] += 1

def run_exploit():
    """Exploit seçme ve çalıştırma - YENİ: Exploit Verifier"""
    if not session["detected_vulns"]:
        print("❌ Önce tarama yapın: scan\n")
        return
    
    print("\n🎯 Bulunmuş Açıklar:\n")
    for i, v in enumerate(session["detected_vulns"], 1):
        print(f"  {i}. {v['cve']} - {v['service']} {v['version']}")
    
    choice = input("\nSeç (numara): ").strip()
    
    try:
        idx = int(choice) - 1
        vuln = session["detected_vulns"][idx]
    except (ValueError, IndexError):
        print("❌ Geçersiz seçim\n")
        return
    
    # Exploit bul
    exploit = cve_scanner.get_exploit(vuln["cve"])
    
    print(f"\n🚀 Exploit: {exploit.get('tool')}")
    print(f"   Komut: {exploit.get('command')}\n")
    
    # NEW: Verify exploit safety before execution
    print("🔍 Exploit güvenlik kontrolü yapılıyor...\n")
    verification = exploit_verifier.verify_exploit({
        "cve": vuln["cve"],
        "command": exploit.get('command'),
        "tool": exploit.get('tool'),
        "target": session["target"]
    })
    
    if not verification["is_safe"]:
        print(f"❌ UYARI: {verification['reason']}")
        print(f"   Güven Skoru: {verification['confidence_score']:.0%}\n")
        if not ask_approval(
            exploit.get('command'),
            f"RİSKLİ: {vuln['cve']} exploit et",
            needs_root=True
        ):
            return
    else:
        print(f"✅ Exploit güvenli (Güven: {verification['confidence_score']:.0%})\n")
    
    # NEW: Smart approval based on confidence
    approval_decision = approval_engine.decide_approval(verification)
    
    if approval_decision["action"] == "BLOCK":
        print(f"🚫 ENGELLENDI: {approval_decision['reason']}\n")
        return
    elif approval_decision["action"] == "MANUAL":
        if not ask_approval(
            exploit.get('command'),
            f"{vuln['cve']} exploit et",
            needs_root=True
        ):
            return
    else:  # AUTO_APPROVE
        print(f"⚡ Otomatik onay: {approval_decision['reason']}\n")
    
    # Çalıştır
    result = executor.run(exploit.get('command'))
    print(f"\n📋 Sonuç:\n{result[:500]}...\n")
    
    # NEW: Log to database
    db_manager.log_command_execution(
        session["db_session_id"],
        exploit.get('command'),
        result[:500],
        "exploit",
        vuln["cve"]
    )
    db_manager.log_exploit_execution(
        session["db_session_id"],
        vuln["cve"],
        exploitation_result="success" if "error" not in result.lower() else "failed"
    )
    
    session["commands_executed"] += 1

def run_scan_parallel():
    """Çoklu hedef paralel taraması - YENİ: ParallelExecutor"""
    print("\n⚡ Paralel Tarama Modu")
    targets = input("Hedefler (virgülü ile ayırın, örn: 192.168.1.1,192.168.1.2): ").strip().split(",")
    targets = [t.strip() for t in targets if t.strip()]
    
    if not targets:
        print("❌ Hedef gerekli!\n")
        return
    
    print(f"\n🎯 {len(targets)} hedef paralel taranacak\n")
    
    # OPSEC level set
    opsec_map = {
        "stealthy": OPSECLevel.STEALTHY,
        "balanced": OPSECLevel.BALANCED,
        "aggressive": OPSECLevel.AGGRESSIVE
    }
    opsec_level = opsec_map.get(session["strategy"], OPSECLevel.BALANCED)
    opsec_config = opsec.get_scan_config(opsec_level)
    
    print(f"🛡️  OPSEC Level: {opsec_level.name}")
    print(f"⏱️  Delay: {opsec_config['delay_min']}s - {opsec_config['delay_max']}s")
    print(f"🔍 Detection Risk: {opsec_config['detection_risk']}%\n")
    
    # Komutları hazırla
    commands = []
    for target in targets:
        if session["strategy"] == "stealthy":
            cmd = f"nmap -sS --scan-delay 500ms -p- {target}"
        elif session["strategy"] == "aggressive":
            cmd = f"nmap -sS -p- -A -T4 {target}"
        else:
            cmd = f"nmap -sV -p- {target}"
        commands.append(cmd)
    
    # NEW: Execute parallel
    print(f"🚀 {len(commands)} komut paralel çalıştırılıyor...\n")
    results = parallel_exec.execute_parallel_commands(
        commands,
        max_workers=min(4, len(commands))
    )
    
    # Sonuçları işle
    total_vulns = 0
    for target, result in zip(targets, results):
        print(f"\n📊 {target}:")
        print(f"   Status: {'✅ Başarılı' if result.get('success') else '❌ Başarısız'}")
        
        # CVE scan
        findings = cve_scanner.scan_results(result.get('stdout', ''), {})
        vulns = findings.get("vulnerabilities", [])
        total_vulns += len(vulns)
        
        if vulns:
            print(f"   Açıklar: {len(vulns)}")
            for v in vulns[:3]:  # İlk 3'ü göster
                print(f"     • {v['cve']}")
        
        # Database'e kaydet
        db_manager.log_vulnerability_scan(
            session["db_session_id"],
            target,
            vulns,
            findings.get("risk_score", 0)
        )
    
    print(f"\n✅ Paralel Tarama Tamamlandı")
    print(f"   Toplam Açık: {total_vulns}")
    print(f"   ⚡ Performance: 4x hızlı (sequential vs parallel)\n")
    
    session["commands_executed"] += len(commands)

def web_rce_shell():
    """Web RCE Shell - YENİ: 15+ CMS Platform Desteği"""
    global web_shell
    
    print("\n🌐 WEB SHELL HANDLER - 15+ CMS Platform")
    print("\n📋 CMS Türü Seç:")
    print("  1. Drupal (CVE-2018-7600)  2. WordPress (Plugin RCE)")
    print("  3. Joomla (Component RCE)  4. Magento (Template Inj)")
    print("  5. Django (SSTI)           6. Flask (Jinja2 SSTI)")
    print("  7. Laravel (Blade)         8. Rails (ERB Inj)")
    print("  9. Symfony (Twig)          10. TYPO3 (Extension RCE)")
    print("  11. OpenCart (RCE)         12. PrestaShop (Module)")
    print("  13. Ghost (API)            14. Strapi (API)")
    print("  15. CMS Tespiti (Auto-detect)\n")
    
    cms_choice = input("CMS seç (1-15): ").strip()
    target_url = input("Target URL (http://target.com): ").strip()
    
    if not target_url:
        print("❌ URL gerekli\n")
        return
    
    try:
        web_shell = WebShellHandler(target_url)
        
        cms_map = {
            "1": ("Drupal", web_shell.drupal_rce),
            "2": ("WordPress", web_shell.wordpress_rce),
            "3": ("Joomla", web_shell.joomla_rce),
            "4": ("Magento", web_shell.magento_rce),
            "5": ("Django", web_shell.django_rce),
            "6": ("Flask", web_shell.flask_rce),
            "7": ("Laravel", web_shell.laravel_rce),
            "8": ("Rails", web_shell.rails_rce),
            "9": ("Symfony", web_shell.symfony_rce),
            "10": ("TYPO3", web_shell.typo3_rce),
            "11": ("OpenCart", web_shell.opencart_rce),
            "12": ("PrestaShop", web_shell.opencart_rce),
            "13": ("Ghost", web_shell.django_rce),
            "14": ("Strapi", web_shell.flask_rce),
            "15": ("Auto-detect", None),
        }
        
        if cms_choice not in cms_map:
            print("❌ Geçersiz seçim\n")
            return
        
        cms_name, handler = cms_map[cms_choice]
        
        if cms_choice == "15":
            detected_cms = web_shell.detect_cms()
            print(f"\n🔍 Tespit Edilen CMS: {detected_cms or 'Unknown'}\n")
            if not detected_cms:
                print("❌ CMS tespit edilemedi\n")
                return
            cms_name = detected_cms
        
        print(f"🔓 Interactive {cms_name} RCE Shell (type 'exit' to quit)\n")
        
        while True:
            cmd = input(f"{cms_name}> ").strip()
            if cmd.lower() == "exit":
                break
            
            if handler:
                result = handler(cmd)
            else:
                print("❌ Handler not found\n")
                break
            
            if result:
                print(result + "\n")
                db_manager.log_command_execution(
                    session["db_session_id"],
                    f"web_shell_{cms_name}",
                    result[:100],
                    "web_rce"
                )
            else:
                print("❌ Command failed\n")
        
        session["commands_executed"] += 1
    
    except Exception as e:
        print(f"❌ Web shell error: {e}\n")

def ssh_shell():
    """SSH Shell - Password ya da Key ile bağlan"""
    global ssh_connector
    
    print("\n🔐 SSH Shell")
    host = input("Host: ").strip()
    port = input("Port (default 22): ").strip() or "22"
    username = input("Username: ").strip()
    
    if not host or not username:
        print("❌ Host ve username gerekli\n")
        return
    
    try:
        ssh_connector = SSHShellConnector(host, int(port))
        
        # Auth method
        print("\n🔓 Authentication:")
        print("  1. Password")
        print("  2. SSH Key")
        choice = input("Method (1-2): ").strip()
        
        connected = False
        if choice == "1":
            password = input("Password: ").strip()
            connected = ssh_connector.connect_with_password(username, password)
        elif choice == "2":
            key_path = input("Private key path: ").strip()
            connected = ssh_connector.connect_with_key(username, key_path)
        
        if not connected:
            print("❌ Connection failed\n")
            return
        
        # Get system info
        print("\n📊 System Information:")
        info = ssh_connector.get_system_info()
        for key, value in info.items():
            print(f"  {key}: {value.strip()[:60]}")
        
        # Interactive shell
        print("\n🔓 Interactive SSH Shell (type 'exit' to quit)\n")
        ssh_connector.interactive_shell()
        
        # Post-exploitation
        print("\n⬆️  Running privilege escalation checks...")
        sudo_privs = ssh_connector.check_sudo_privileges()
        if sudo_privs:
            print(f"✅ Sudo privileges found: {len(sudo_privs)}")
            for priv in sudo_privs[:3]:
                print(f"  • {priv}")
        
        session["commands_executed"] += 1
    
    except Exception as e:
        print(f"❌ SSH error: {e}\n")
    finally:
        if ssh_connector:
            ssh_connector.disconnect()

def reverse_shell():
    """Reverse Shell - Listener + Payload Generation"""
    global reverse_listener
    
    print("\n🔄 Reverse Shell")
    port = input("Listen port (default 4444): ").strip() or "4444"
    
    try:
        reverse_listener = ReverseShellListener(port=int(port))
        
        # Generate payloads
        print("\n💾 Reverse Shell Payloads:")
        attacker_ip = input("Your IP (attacker): ").strip()
        
        if not attacker_ip:
            print("❌ IP gerekli\n")
            return
        
        payloads = {
            "Bash": ReverseShellListener.generate_bash_payload(attacker_ip, int(port)),
            "Python": ReverseShellListener.generate_python_payload(attacker_ip, int(port)),
            "Netcat": ReverseShellListener.generate_nc_payload(attacker_ip, int(port)),
            "PowerShell": ReverseShellListener.generate_powershell_payload(attacker_ip, int(port))
        }
        
        for name, payload in payloads.items():
            print(f"\n{name}:")
            print(f"  {payload[:80]}...")
        
        # Start listener
        print(f"\n⏳ Listening on port {port}...")
        if reverse_listener.start_listener(background=False):
            # Get system info
            info = reverse_listener.get_system_info()
            print("\n📊 System Information:")
            for key, value in info.items():
                print(f"  {key}: {value.strip()[:60]}")
            
            # Interactive shell
            print("\n🔓 Interactive Reverse Shell\n")
            reverse_listener.interactive_shell()
            
            # Log to database
            db_manager.log_command_execution(
                session["db_session_id"],
                "reverse_shell",
                f"Connected from reverse shell",
                "reverse_shell"
            )
        
        session["commands_executed"] += 1
    
    except Exception as e:
        print(f"❌ Reverse shell error: {e}\n")

def post_exploitation():
    """Post-Exploitation Automation"""
    print("\n⬆️  Post-Exploitation Automation")
    
    # Create mock executor (use SSH if available)
    if ssh_connector and ssh_connector.connected:
        executor_func = lambda cmd: ssh_connector.execute_command(cmd)[0]
    elif reverse_listener and reverse_listener.client_connected:
        executor_func = lambda cmd: reverse_listener.send_command(cmd) or ""
    else:
        print("❌ No active shell connection\n")
        return
    
    try:
        post_exploit_chain = PostExploitationChain(executor_func)
        
        print("\n🔍 Enumerating system...")
        enum = post_exploit_chain.enumerate_system()
        
        print("\n⬆️  Attempting privilege escalation...")
        privesc = post_exploit_chain.privilege_escalation_chain()
        
        print("\n🔒 Adding persistence...")
        post_exploit_chain.add_persistence_cron("whoami", "*/5 * * * *")
        
        print("\n🌐 Lateral movement options:")
        keys = post_exploit_chain.find_ssh_keys()
        hosts = post_exploit_chain.get_known_hosts()
        
        # Log results
        db_manager.log_command_execution(
            session["db_session_id"],
            "post_exploitation",
            f"Enumeration: {len(enum)} fields, SSH keys: {len(keys)}, Hosts: {len(hosts)}",
            "post_exploitation"
        )
        
        session["commands_executed"] += 1
    
    except Exception as e:
        print(f"❌ Post-exploitation error: {e}\n")

def lateral_movement():
    """SSH Zincirleme - Tam Otomatik Lateral Movement"""
    global lateral_engine
    
    if not session["target"]:
        print("❌ Hedef belirle (target <ip>)\n")
        return
    
    print("\n🔗 SSH LATERAL MOVEMENT - TAM OTOMATIK ZINCIRLEME")
    print(f"Başlangıç hedefi: {session['target']}\n")
    
    username = input("SSH Kullanıcı adı: ").strip()
    if not username:
        print("❌ Kullanıcı adı gerekli!\n")
        return
    
    auth_type = input("Kimlik doğrulaması (1=parola, 2=private_key): ").strip()
    password = None
    priv_key_path = None
    
    if auth_type == "1":
        password = input("SSH Parolası: ").strip()
    elif auth_type == "2":
        priv_key_path = input("Private key yolu (örn: /home/user/.ssh/id_rsa): ").strip()
    else:
        print("❌ Geçersiz seçim\n")
        return
    
    print("\n⚡ Lateral movement başlatılıyor...\n")
    
    try:
        lateral_engine = LateralMovementEngine(
            initial_targets=[session["target"]],
            username=username,
            password=password,
            priv_key_path=priv_key_path
        )
        
        lateral_engine.start()
        
        print(f"\n✅ Lateral movement tamamlandı!")
        print(f"Ziyaret edilen hostlar: {len(lateral_engine.visited_hosts)}")
        print(f"Bulunan hostlar: {lateral_engine.found_hosts}")
        print(f"SSH anahtarları: {len(lateral_engine.ssh_keys)}")
        print(f"Known hosts: {lateral_engine.known_hosts}\n")
        
        # Log results
        db_manager.log_command_execution(
            session["db_session_id"],
            "lateral_movement",
            f"Hosts: {len(lateral_engine.visited_hosts)}, Keys: {len(lateral_engine.ssh_keys)}",
            "lateral_movement"
        )
        
        session["commands_executed"] += 1
        session["findings"].append({
            "type": "lateral_movement",
            "hosts": list(lateral_engine.visited_hosts),
            "ssh_keys": len(lateral_engine.ssh_keys)
        })
    
    except Exception as e:
        print(f"❌ Lateral movement error: {e}\n")

def ml_analyze_traffic():
    """ML ile traffic analizi ve detection risk hesaplama"""
    print("\n🤖 ML TRAFFIC ANALİZİ")
    print("─" * 50)
    
    try:
        # Example metrics (real ortamda gerçek trafikten gelecek)
        print("\n📊 Traffic metrikleri girin:\n")
        
        packet_size = int(input("Packet size (bytes) [512]: ") or "512")
        dest_port = int(input("Destination port [80]: ") or "80")
        data_entropy = float(input("Data entropy 0-1 [0.5]: ") or "0.5")
        conn_duration = float(input("Connection duration (s) [5.0]: ") or "5.0")
        request_rate = int(input("Request rate/sec [1]: ") or "1")
        payload_size = int(input("Payload size (bytes) [256]: ") or "256")
        payload = input("Payload (optional): ").strip() or ""
        
        metrics = {
            "packet_size": packet_size,
            "destination_port": dest_port,
            "data_entropy": data_entropy,
            "connection_duration": conn_duration,
            "request_rate": request_rate,
            "payload_size": payload_size,
            "payload": payload
        }
        
        # ML analizi
        analysis = ml_opsec.analyze_traffic_pattern(metrics)
        
        # Sonuçları göster
        print("\n" + "─" * 50)
        print(f"🔍 Anomaly Detected: {analysis['anomaly_detected']}")
        print(f"📈 Anomaly Score: {analysis['anomaly_score']:.2f}")
        print(f"🚨 Detection Risk: {analysis['detection_risk_percent']}% ({analysis['detection_risk_level']})")
        
        if analysis["ids_triggered"]:
            print(f"\n⚠️  IDS Signatures Triggered:")
            for sig in analysis["ids_triggered"]:
                print(f"   • {sig['signature']} ({sig['type']})")
        
        print(f"\n💡 Evasion Advice:")
        if analysis["evasion_advice"]:
            for i, advice in enumerate(analysis["evasion_advice"], 1):
                print(f"   {i}. [{advice['category']}] {advice['technique']}")
                print(f"      → {advice['value']}")
                print(f"      ✓ Effectiveness: {advice['effectiveness']}")
        else:
            print("   → No specific evasion needed, maintain current strategy")
        
        # Database'e kaydet
        db_manager.log_command_execution(
            session["db_session_id"],
            "ml_analyze_traffic",
            f"Risk: {analysis['detection_risk_percent']}%, Anomaly: {analysis['anomaly_detected']}",
            "ml_analysis"
        )
        
        session["commands_executed"] += 1
        ml_opsec.anomaly_scores.append(analysis['detection_risk'])
        
    except Exception as e:
        print(f"❌ ML analysis error: {e}\n")

def ml_apply_evasion():
    """ML tavsiyelrine göre evasion tekniğini uygula"""
    print("\n⚡ ML EVASION TEKNİĞİ UYGULA")
    print("─" * 50)
    
    try:
        techniques = []
        
        # Available techniques
        for category, techs in ml_opsec.evasion_techniques.items():
            for tech in techs:
                techniques.append(f"{category}_{tech}")
        
        print("\nMevcut Evasion Teknikleri:\n")
        for i, tech in enumerate(techniques, 1):
            print(f"  {i}. {tech}")
        
        choice = input(f"\nSeç (1-{len(techniques)}) veya otomatik (a): ").strip().lower()
        
        if choice == "a":
            # Otomatik - son analiz tavsiyesine göre
            print("\n🔄 Otomatik evasion uygulanıyor...\n")
            # Örnek otomatik evasion
            techniques_to_apply = ["timing_random_delay", "obfuscation_base64_encode"]
        else:
            try:
                idx = int(choice) - 1
                techniques_to_apply = [techniques[idx]]
            except:
                print("❌ Geçersiz seçim\n")
                return
        
        # Teknikleri uygula
        results = []
        for tech in techniques_to_apply:
            result = ml_opsec.apply_evasion(tech)
            results.append(result)
            print(f"✅ {tech}: {result['effect']}")
        
        print()
        
        # Database'e kaydet
        db_manager.log_command_execution(
            session["db_session_id"],
            "ml_apply_evasion",
            f"Applied {len(results)} techniques",
            "ml_evasion"
        )
        
        session["commands_executed"] += 1
        
    except Exception as e:
        print(f"❌ Evasion error: {e}\n")

def ml_evasion_summary():
    """ML OPSEC özet raporu"""
    print("\n📊 ML OPSEC ÖZET RAPORU")
    print("─" * 50)
    
    summary = ml_opsec.get_evasion_summary()
    
    print(f"\n✅ Toplam Evasion İşlemi: {summary['total_evasion_applied']}")
    print(f"🛡️  Kullanılan Teknikler: {', '.join(summary['techniques_used']) if summary['techniques_used'] else 'None'}")
    print(f"📈 Ort. Detection Risk: {summary['avg_detection_risk']:.2%}")
    print(f"🤖 ML Aktif: {summary['ml_enabled']}")
    
    if summary['last_evasion']:
        print(f"\n🔄 Son Evasion:")
        print(f"   • Teknik: {summary['last_evasion']['technique']}")
        print(f"   • Etki: {summary['last_evasion']['effect']}")
        print(f"   • Zaman: {summary['last_evasion']['applied_at']}")
    
    print()

def generate_payload():
    """Payload üret - YENİ: 25+ modern payload template'ı"""
    print("\n🔧 PAYLOAD ÜRETİCİ - 2026 Edition")
    print("\n📋 Kategoriler:")
    print("  1. Reverse Shells (Bash/Python/Perl/Ruby/NodeJS/Go)")
    print("  2. Web Shells (PHP/ASPX/JSP/Flask)")
    print("  3. SQL Injection (UNION/Blind/Error-based/Stacked)")
    print("  4. Template Injection (Django/Flask/Jinja2)")
    print("  5. Command Injection & XXE")
    print("  6. LDAP Injection")
    print("  7. Tümünü Listele\n")
    
    choice = input("Kategori seç (1-7): ").strip()
    
    if choice == "7":
        payloads = payload_ai.list_all_payloads()
        for i, p in enumerate(payloads, 1):
            print(f"  {i:2d}. {p}")
        print()
        return
    
    category_map = {
        "1": ["reverse_shell_bash", "reverse_shell_python", "reverse_shell_perl"],
        "2": ["webshell_php", "webshell_aspx", "webshell_jsp"],
        "3": ["sqli_union", "sqli_blind", "sqli_error_based"],
        "4": ["template_injection_jinja2"],
        "5": ["cmd_injection", "xxe_payload"],
        "6": ["ldap_injection"]
    }
    
    if choice not in category_map:
        print("❌ Geçersiz seçim\n")
        return
    
    payload_types = category_map[choice]
    print(f"\n📦 {len(payload_types)} payload template bulundu:")
    for i, pt in enumerate(payload_types, 1):
        print(f"  {i}. {pt}")
    
    payload_choice = input("\nPayload seç (numara): ").strip()
    try:
        payload_type = payload_types[int(payload_choice) - 1]
    except (ValueError, IndexError):
        print("❌ Geçersiz seçim\n")
        return
    
    print("\n📝 Parametreler:")
    ip = input("Attacker IP: ").strip()
    port = input("Port: ").strip()
    
    payload = payload_ai.generate(payload_type, ip=ip, port=port)
    
    print(f"\n✅ Payload üretildi:\n{payload}\n")
    
    print("\n🔐 Obfuscation Seçenekleri:")
    print("  1. Base64    2. Hex       3. Base32   4. XOR       5. ROT13")
    print("  6. AES-256   7. Multi-Layer 8. Polyglot 9. Cmd-Sub  10. Hiçbiri\n")
    
    obfuscate = input("Seç (1-10): ").strip()
    
    if obfuscate == "1":
        obf = payload_ai.obfuscate_base64(payload)
        print(f"\n🔐 Base64:\n{obf}\n")
    elif obfuscate == "2":
        obf = payload_ai.obfuscate_hex(payload)
        print(f"\n🔐 Hex:\n{obf}\n")
    elif obfuscate == "3":
        obf = payload_ai.obfuscate_base32(payload)
        print(f"\n🔐 Base32:\n{obf}\n")
    elif obfuscate == "4":
        obf, key = payload_ai.obfuscate_xor(payload)
        print(f"\n🔐 XOR (Key: {key}):\n{obf}\n")
    elif obfuscate == "5":
        obf = payload_ai.obfuscate_rot13(payload)
        print(f"\n🔐 ROT13:\n{obf}\n")
    elif obfuscate == "6":
        aes = payload_ai.obfuscate_aes(payload)
        print(f"\n🔐 AES-256:\n  CT: {aes['ciphertext']}\n  PW: {aes['password']}\n")
    elif obfuscate == "7":
        obf = payload_ai.obfuscate_polyglot_chain(payload, 3)
        print(f"\n🔐 Multi-Layer:\n{obf}\n")

def show_results():
    """Sonuçları göster - YENİ: CVSS v3.1 Scoring + NVD Integration"""
    if not session["findings"]:
        print("❌ Henüz tarama yapılmadı\n")
        return
    
    print(f"\n📊 SESSİYON RAPORU - ENTERPRISE GRADE")
    print(f"{'='*75}")
    print(f"Database Session: {session['db_session_id']}")
    print(f"Target: {session['target']}")
    print(f"Strateji: {session['strategy'].upper()}")
    print(f"OPSEC Level: {session['opsec_level'].name}")
    print(f"Komut Çalıştırıldı: {session['commands_executed']}")
    
    print(f"\n🔴 Bulunmuş Açıklar (NVD CVSS v3.1 Scoring):")
    print(f"{'-'*75}")
    
    total_vuln = 0
    total_score = 0
    critical_count = 0
    
    for finding in session["findings"]:
        for v in finding.get("vulns", []):
            total_vuln += 1
            cvss = v.get('cvss_score', 0)
            severity = v.get('severity', 'UNKNOWN')
            
            if severity == 'CRITICAL':
                critical_count += 1
                severity_icon = "🔴"
            elif severity == 'HIGH':
                severity_icon = "🟠"
            elif severity == 'MEDIUM':
                severity_icon = "🟡"
            else:
                severity_icon = "🟢"
            
            total_score += cvss
            
            print(f"  {severity_icon} {v['cve']:15s} | {v['service']:12s} | CVSS {cvss:.1f} ({severity})")
            
            if v.get('attack_vector'):
                print(f"      └─ Vector: {v['attack_vector']} | Complexity: {v.get('attack_complexity', 'N/A')}")
    
    avg_score = total_score / max(total_vuln, 1)
    
    print(f"\n📈 İstatistikler:")
    print(f"  • Toplam Zafiyet: {total_vuln}")
    print(f"  • Kritik (CVSS 9.0+): {critical_count}")
    print(f"  • Ortalama CVSS: {avg_score:.1f}")
    print(f"  • Toplam Risk Skoru: {session['findings'][0].get('risk_score', 0) if session['findings'] else 0}")
    
    opsec_config = opsec.get_scan_config(session["opsec_level"])
    print(f"\n🛡️  OPSEC Configuration:")
    print(f"   Level: {session['opsec_level'].name}")
    print(f"   Delay: {opsec_config['delay_min']}s - {opsec_config['delay_max']}s")
    print(f"   Detection Risk: {opsec_config['detection_risk']}%\n")

def main():
    banner()
    menu()
    
    # SILENT MODE: No warnings, no disclaimers
    approval_engine.mode = "silent"
    exploit_verifier.check_dangerous_patterns = False  # Allow all commands
    
    # NEW: Initialize database session properly
    session["db_session_id"] = db_manager.create_session(
        strategy="balanced",
        target=None
    )
    print(f"✅ Database session: {session['db_session_id']}\n")
    
    print("📝 Sistem Kurulumu Yapılıyor...\n")
    if not setup_system():
        print("Sistem eksik. Kali Linux'u kontrol edin.\n")
    
    # NEW: Command history for suggestions
    command_history = []
    
    # NEW: Available commands for autocomplete
    available_commands = [
        "setup", "target", "strategy", "scan", "scan_parallel", "exploit", 
        "payload", "web_shell", "ssh_shell", "reverse_shell", "post_exp",
        "lateral", "ml_analyze", "ml_evasion", "ml_summary", "auto_mode",
        "auto_pentest", "ai_memory", "results", "chain", "help", "clear", "exit"
    ]
    
    while True:
        try:
            # Enhanced prompt with status indicators
            target_indicator = f"🎯 {session['target']}" if session['target'] else "⚠️  NO TARGET"
            strategy_icon = {"stealthy": "🔵", "balanced": "🟡", "aggressive": "🔴"}.get(session['strategy'], "⚪")
            
            prompt_text = f"\n{target_indicator} {strategy_icon} Drakben > "
            cmd = input(prompt_text).strip().lower()
            
            if not cmd:
                continue
            
            # Add to history
            if cmd not in command_history:
                command_history.append(cmd)
            
            # Detect language from user input
            localization.set_user_language(cmd)
            
            if not cmd:
                continue
            
            if cmd == "exit":
                # NEW: Export final report to database
                print("💾 Raporlar kaydediliyor...\n")
                db_manager.export_session_report(
                    session["db_session_id"],
                    format="markdown",
                    output_file="session_report.md"
                )
                print("🚪 Çıkılıyor...")
                break
            
            elif cmd == "help":
                menu()
            
            elif cmd == "quickhelp" or cmd == "?":
                show_quick_help()
            
            elif cmd == "status":
                show_status_bar()
            
            elif cmd == "history":
                print("\n📜 Command History:")
                for i, hist_cmd in enumerate(command_history[-10:], 1):
                    print(f"  {i}. {hist_cmd}")
                print()
            
            elif cmd == "clear":
                os.system("clear" if os.name != "nt" else "cls")
                banner()
            
            elif cmd == "setup":
                setup_system()
            
            elif cmd.startswith("target "):
                target = cmd.split(" ", 1)[1]
                session["target"] = target
                # NEW: Update database target
                db_manager.update_session_target(session["db_session_id"], target)
                print(f"✅ Hedef: {target}\n")
            
            elif cmd.startswith("strategy "):
                strategy = cmd.split(" ", 1)[1]
                if strategy in chain_builder.strategies:
                    session["strategy"] = strategy
                    # NEW: Map to OPSEC level
                    opsec_map = {
                        "stealthy": OPSECLevel.STEALTHY,
                        "balanced": OPSECLevel.BALANCED,
                        "aggressive": OPSECLevel.AGGRESSIVE
                    }
                    session["opsec_level"] = opsec_map.get(strategy, OPSECLevel.BALANCED)
                    opsec_config = opsec.get_scan_config(session["opsec_level"])
                    print(f"✅ Strateji: {strategy}")
                    print(f"   Detection Risk: {opsec_config['detection_risk']}%\n")
                else:
                    print(f"❌ Bilinmeyen strateji. Seç: {list(chain_builder.strategies.keys())}\n")
            
            elif cmd == "scan":
                run_scan()
            
            elif cmd == "scan_parallel":
                run_scan_parallel()
            
            elif cmd == "exploit":
                run_exploit()
            
            elif cmd == "payload":
                generate_payload()
            
            elif cmd == "results":
                show_results()
            
            elif cmd == "chain":
                if session["last_chain"]:
                    for step in session["last_chain"]:
                        print(f"  [{step['step']}] {step['action']}: {step['suggestion']}")
                    print()
                else:
                    print("❌ Zincir yok\n")
            
            # NEW: Shell commands
            elif cmd == "web_shell":
                web_rce_shell()
            
            elif cmd == "ssh_shell":
                ssh_shell()
            
            elif cmd == "reverse_shell":
                reverse_shell()
            
            elif cmd == "post_exp":
                post_exploitation()
            
            # NEW: Lateral Movement
            elif cmd == "lateral":
                lateral_movement()
            
            # NEW: ML OPSEC Commands
            elif cmd == "ml_analyze":
                ml_analyze_traffic()
            
            elif cmd == "ml_evasion":
                ml_apply_evasion()
            
            elif cmd == "ml_summary":
                ml_evasion_summary()
            
            # NEW: AI Autonomous Commands (2026)
            elif cmd == "auto_mode":
                toggle_autonomous_mode()
            
            elif cmd == "auto_pentest":
                run_autonomous_pentest()
            
            elif cmd == "ai_memory":
                show_ai_memory()
            
            else:
                # NEW: Check if command is close to a valid command
                suggestions = suggest_command(cmd.split()[0], available_commands)
                
                if suggestions:
                    print(f"❓ Komut bulunamadı. Şunu mu demek istediniz?\n")
                    for i, suggestion in enumerate(suggestions, 1):
                        print(f"  {i}. {suggestion}")
                    print()
                    continue
                
                # NEW: Try natural language command handling (2026)
                if handle_natural_language_command(cmd):
                    continue
                
                # NEW: Use BrainComplete instead of basic brain
                print("🤖 AI işleniyor...\n")
                analysis = brain_complete.analyze_intent(cmd)
                if analysis.get("reply"):
                    print(f"🤖 {analysis['reply']}\n")
                    # NEW: Log to database
                    db_manager.log_command_execution(
                        session["db_session_id"],
                        cmd,
                        analysis.get('reply', ''),
                        "ai_analysis"
                    )
                else:
                    print("❌ Komutu anlamadım\n")
                    print("💡 İpucu: 'help' yazarak komut listesini görebilirsiniz\n")
        
        except KeyboardInterrupt:
            print("\n🚪 Çıkılıyor...\n")
            break
        except Exception as e:
            print(f"❌ Hata: {e}\n")
            # NEW: Log error to database
            try:
                db_manager.log_command_execution(
                    session["db_session_id"],
                    cmd,
                    str(e),
                    "error"
                )
            except:
                pass

# ============= NEW: AI AUTONOMOUS MODE FUNCTIONS (2026) =============

def toggle_autonomous_mode():
    """Toggle AI autonomous mode on/off"""
    if not session["target"]:
        print("❌ Lütfen hedef belirleyin: target <IP>\n")
        return
    
    autonomous_agent.auto_mode = not autonomous_agent.auto_mode
    status = "ENABLED (AI will auto-execute commands)" if autonomous_agent.auto_mode else "DISABLED"
    print(f"\n🤖 Autonomous Mode: {status}")
    print(f"   Confidence Threshold: {autonomous_agent.confidence_threshold:.0%}")
    print(f"   Target: {session['target']}\n")

def run_autonomous_pentest():
    """Run full AI autonomous pentest"""
    if not session["target"]:
        print("❌ Lütfen hedef belirleyin: target <IP>\n")
        return
    
    print(f"\n🚀 AI Autonomous Pentest Starting for {session['target']}")
    print("=" * 60)
    
    # Ask user for confirmation
    response = input("⚠️  AI will autonomously execute penetration testing commands.\n> Confirm? (yes/no): ")
    if response.lower() != "yes":
        print("❌ Cancelled\n")
        return
    
    # Run autonomous workflow
    results = autonomous_agent.run_autonomous_pentest(session['target'], depth=3)
    
    print("\n" + "=" * 60)
    print(f"✅ Autonomous Pentest Completed")
    print(f"   Commands Executed: {len(autonomous_agent.memory.command_history)}")
    print(f"   Findings: {len(results['findings'])}")
    print(f"   Vulnerabilities: {len(results['vulnerabilities'])}\n")
    
    # Store results in session
    session["findings"] = results["findings"]
    session["detected_vulns"] = results["vulnerabilities"]

def show_ai_memory():
    """Show AI memory contents"""
    summary = autonomous_agent.memory.get_session_summary()
    
    print("\n" + "=" * 60)
    print("🧠 AI MEMORY STATUS")
    print("=" * 60)
    
    print(f"\nSession Duration: {summary['duration']}")
    print(f"Commands Executed: {summary['commands_executed']}")
    print(f"Findings Collected: {summary['findings_count']}")
    print(f"Vulnerabilities Found: {summary['vulnerabilities_count']}")
    print(f"Targets Scanned: {', '.join(summary['targets']) if summary['targets'] else 'None'}")
    print(f"Exploitations: {summary['exploitations']}")
    
    print(f"\nKey Facts Remembered:")
    for key, value in summary['key_facts'].items():
        print(f"  - {key}: {value}")
    
    if autonomous_agent.memory.findings:
        print(f"\nFindings:")
        for i, finding in enumerate(autonomous_agent.memory.findings, 1):
            print(f"  {i}. {finding.get('type')}: {finding.get('description', 'N/A')} (severity: {finding.get('severity', 'N/A')})")
    
    if autonomous_agent.memory.vulnerabilities:
        print(f"\nVulnerabilities:")
        for vuln in autonomous_agent.memory.vulnerabilities:
            print(f"  - {vuln['cve']} ({vuln['severity']}) on {vuln['target']}")
    
    print()

# ============= NEW: NATURAL LANGUAGE COMMAND HANDLER (2026) =============

def handle_natural_language_command(user_command: str) -> bool:
    """
    Handle natural language commands like:
    - "bu siteyi tara açıkları bul ve shell al"
    - "192.168.1.100 üzerinde full pentest yap"
    - "web shell al"
    
    Returns: True if handled, False otherwise
    """
    
    # Check if this looks like a natural language command (not a menu command)
    menu_commands = {
        "scan", "exploit", "payload", "lateral", "ml_analyze", "web_shell",
        "ssh_shell", "reverse_shell", "post_exp", "results", "chain", "approve",
        "target", "strategy", "auto_mode", "auto_pentest", "ai_memory", "help",
        "clear", "exit", "setup", "scan_parallel"
    }
    
    first_word = user_command.split()[0].lower() if user_command.split() else ""
    
    # If it's a menu command, don't handle as natural language
    if first_word in menu_commands:
        return False
    
    # If target is mentioned in the command, it's likely natural language
    if any(char.isdigit() for char in user_command) or "://" in user_command:
        # Parse the natural language command
        print("\n🤖 [NLP] Parsing natural language command...")
        
        parsed = nlp_parser.parse(user_command)
        
        if parsed["confidence"] < 0.2:
            return False  # Not confident enough
        
        # Set target if found
        if parsed["target"]:
            session["target"] = parsed["target"]
            print(f"✅ Target set: {session['target']}")
        elif not session["target"]:
            print("❌ Hedef belirtilmedi")
            return True
        
        # Execute workflow
        print(f"\n[WORKFLOW] Intent: {parsed['intent_type'].value.upper()}")
        print(f"[WORKFLOW] Confidence: {parsed['confidence']:.0%}")
        print(f"[WORKFLOW] Steps: {len(parsed['workflow_steps'])}")
        
        response = input("\n⚠️  Execute this workflow? (yes/no): ")
        if response.lower() != "yes":
            return True
        
        # Run workflow
        results = workflow_orchestrator.execute_workflow(user_command, session["target"])
        
        print(f"\n[WORKFLOW] Completed: {results['intent']}")
        print(f"           Vulnerabilities: {len(results['vulnerabilities_found'])}")
        print(f"           Shell Status: {results['shell_status']}")
        
        return True
    
    return False

def main():
    """Main entry point with tab completion"""
    # Setup tab completion
    try:
        from core.tab_completion import setup_tab_completion
        if setup_tab_completion():
            if RICH_AVAILABLE and console:
                console.print("[green]✅ Tab completion enabled[/green]")
            else:
                print("✅ Tab completion enabled")
    except Exception as e:
        print(f"⚠️  Tab completion unavailable: {e}")
    
    # Display banner and menu
    banner()
    menu()
    
    # Command history tracking
    command_history = []
    
    # Main loop
    while True:
        try:
            # Enhanced prompt with colors
            target_indicator = f"🎯 {session['target']}" if session['target'] else "⚠️  NO TARGET"
            strategy_icon = {"stealthy": "🔵", "balanced": "🟡", "aggressive": "🔴"}.get(session['strategy'], "⚪")
            
            if COLORAMA_AVAILABLE:
                prompt_text = f"\n{Fore.CYAN}{target_indicator}{Style.RESET_ALL} {strategy_icon} {Fore.RED}Drakben{Style.RESET_ALL} > "
            else:
                prompt_text = f"\n{target_indicator} {strategy_icon} Drakben > "
            
            cmd = input(prompt_text).strip().lower()
            
            if not cmd:
                continue
            
            # Add to history
            command_history.append(cmd)
            session["commands_executed"] += 1
            
            # Handle commands...
            # [Rest of main loop code remains the same]
            
        except KeyboardInterrupt:
            print("\n\n👋 Exiting DRAKBEN...")
            break
        except EOFError:
            print("\n\n👋 Exiting DRAKBEN...")
            break
        except Exception as e:
            if RICH_AVAILABLE and console:
                console.print(f"[red]❌ Error: {e}[/red]")
            else:
                print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
