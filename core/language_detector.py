# core/language_detector.py
# Multi-Language Support for Turkish/English
# 2026 - Automatic Language Detection & Response

from typing import Dict, Literal, Any
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

Language = Literal["tr", "en"]

class LanguageDetector:
    """Detect user language from input text"""
    
    def __init__(self):
        # Turkish keywords
        self.turkish_keywords = {
            "tara", "aç", "bul", "yap", "al", "gir", "kaçış", "göster",
            "komut", "yardım", "çıkış", "temizle", "hedef", "strateji",
            "exploit", "şifre", "ağ", "veritabanı", "güvenlik", "kullanıcı",
            "zaafiyeti", "cve", "port", "servis", "versiyonu", "dosya",
            "ssh", "rdp", "shell", "reverse", "payload", "payload üret",
            "pentest", "priv", "privesc", "lateral", "pivoting", "exfil",
            "otomatik", "onay", "onaylı", "hafıza", "hatırla", "bellek",
            "tarama", "taradı", "taradığını", "taradığımız", "taranıyor",
            "açıkları", "açıklar", "zaafiyetleri", "zaafiyet", "rce",
            "siteyi", "siteye", "sitesi", "sunucusunun", "sunucuya",
            "admin", "root", "administrator", "sistem", "windows", "linux",
            "üzerinde", "için", "ile", "dan", "e", "den", "ni", "nı",
            "böyle", "mi", "mı", "mu", "mü", "dimi", "var", "yok", "var",
            "başla", "başlar", "başlat", "başlatıyor", "başladı",
        }
        
        # English keywords
        self.english_keywords = {
            "scan", "exploit", "shell", "payload", "target", "pentest",
            "vulnerability", "cve", "port", "service", "access", "root",
            "password", "brute", "force", "rce", "sqli", "xss", "lfi",
            "web", "database", "network", "lateral", "movement", "privesc",
            "escalation", "memory", "execute", "command", "help", "exit",
            "clear", "show", "display", "find", "discover", "scan",
            "enumerate", "identify", "detect", "analyze", "threat",
            "risk", "danger", "safe", "unsafe", "approve", "deny",
            "confirm", "verify", "validate", "check", "status", "result",
            "complete", "start", "begin", "finish", "end", "run", "execute",
            "automatic", "manual", "autonomous", "agent", "ai", "memory",
            "hello", "how", "are", "you", "what", "when", "where", "why",
            "the", "is", "and", "or", "not", "this", "that", "these", "those",
        }
    
    def detect(self, text: str) -> Language:
        """
        Detect language from input text
        Returns: "tr" for Turkish, "en" for English
        """
        text_lower = text.lower()
        
        turkish_count = sum(1 for word in self.turkish_keywords if word in text_lower)
        english_count = sum(1 for word in self.english_keywords if word in text_lower)
        
        # Character-based detection (Turkish-specific characters)
        turkish_chars = text.count('ç') + text.count('ğ') + text.count('ı') + \
                       text.count('ö') + text.count('ş') + text.count('ü') + \
                       text.count('Ç') + text.count('Ğ') + text.count('İ') + \
                       text.count('Ö') + text.count('Ş') + text.count('Ü')
        
        # Calculate confidence
        if turkish_chars > 0:
            return "tr"
        
        if english_count > turkish_count:
            return "en"
        elif turkish_count > english_count:
            return "tr"
        else:
            # Default to English if unclear
            return "en"
    
    def get_language_name(self, lang: Language) -> str:
        """Get language name"""
        return "Türkçe" if lang == "tr" else "English"


class LocalizationManager:
    """Manage multi-language support and dynamic response generation"""
    
    def __init__(self):
        self.detector = LanguageDetector()
        self.responses = MultiLanguageResponses()
        self.session_language = "tr"  # Default language
    
    def detect_and_set_language(self, user_input: str):
        """Detect language from user input and update session"""
        self.session_language = self.detector.detect(user_input)
        logger.info(f"Language detected: {self.session_language}")
    
    def get_response(self, key: str, **kwargs) -> str:
        """Get localized response for given key"""
        return self.responses.get(key, self.session_language, **kwargs)
    
    def switch_language(self, lang: Language):
        """Manually switch language"""
        self.session_language = lang
        logger.info(f"Language switched to: {lang}")


class MultiLanguageResponses:
    """Store and retrieve multi-language responses"""
    
    def __init__(self):
        self.responses = {
            # MENU
            "menu_banner": {
                "tr": """
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║            🩸 D R A K B E N  v4.0 - 2026 🩸             ║
║                                                          ║
║        AI-Destekli Penetrasyon Test Platformu           ║
║                                                          ║
║   ⚡ Otomatik Zafiyet Keşfi & Exploit Automation        ║
║   🔍 Zero-Day Detection & CVE Intelligence              ║
║   🛡️ OPSEC-Aware Stratejiler (Stealth/Aggressive)      ║
║   🤖 Machine Learning ile Tehdit Analizi                ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
""",
                "en": """
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║            🩸 D R A K B E N  v4.0 - 2026 🩸             ║
║                                                          ║
║        AI-Powered Penetration Testing Platform          ║
║                                                          ║
║   ⚡ Automated Vulnerability Discovery & Exploitation   ║
║   🔍 Zero-Day Detection & CVE Intelligence              ║
║   🛡️ OPSEC-Aware Strategies (Stealth/Aggressive)       ║
║   🤖 Machine Learning Threat Analysis                   ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
""",
            },
            
            # PROMPTS
            "prompt_command": {
                "tr": "Komutu girin: ",
                "en": "Enter command: ",
            },
            
            "prompt_target": {
                "tr": "Hedef belirtilmedi. Kullan: target <IP>\n",
                "en": "Target not specified. Use: target <IP>\n",
            },
            
            "prompt_confirm": {
                "tr": "\nBu workflow'u çalıştır? (evet/hayır): ",
                "en": "\nExecute this workflow? (yes/no): ",
            },
            
            "prompt_approve_exploit": {
                "tr": "\nExploit çalıştır? (evet/hayır): ",
                "en": "\nRun exploit? (yes/no): ",
            },
            
            # STATUS MESSAGES
            "target_set": {
                "tr": "✅ Hedef ayarlandı: {target}\n",
                "en": "✅ Target set: {target}\n",
            },
            
            "strategy_set": {
                "tr": "✅ Strateji: {strategy}\n   Tespit Riski: {risk}%\n",
                "en": "✅ Strategy: {strategy}\n   Detection Risk: {risk}%\n",
            },
            
            "nlp_parsing": {
                "tr": "\n🤖 [NLP] Doğal dil komutu analiz ediliyor...\n",
                "en": "\n🤖 [NLP] Parsing natural language command...\n",
            },
            
            "workflow_intent": {
                "tr": "[WORKFLOW] Amaç: {intent}\n[WORKFLOW] Güven: {confidence}%\n[WORKFLOW] Hedef: {target}\n",
                "en": "[WORKFLOW] Intent: {intent}\n[WORKFLOW] Confidence: {confidence}%\n[WORKFLOW] Target: {target}\n",
            },
            
            "workflow_executing": {
                "tr": "[WORKFLOW] {count} adım çalıştırılıyor:\n",
                "en": "[WORKFLOW] Executing {count} steps:\n",
            },
            
            "workflow_completed": {
                "tr": "[WORKFLOW] Tamamlandı: {intent}\n           Zaafiyet: {vuln_count}\n           Shell Durumu: {shell_status}\n",
                "en": "[WORKFLOW] Completed: {intent}\n           Vulnerabilities: {vuln_count}\n           Shell Status: {shell_status}\n",
            },
            
            # AUTONOMOUS MODE
            "auto_mode_enabled": {
                "tr": "\n🤖 Özerk Mod: AÇIK (AI otomatik komut çalıştıracak)\n",
                "en": "\n🤖 Autonomous Mode: ENABLED (AI will auto-execute commands)\n",
            },
            
            "auto_mode_disabled": {
                "tr": "\n🤖 Özerk Mod: KAPAL\n",
                "en": "\n🤖 Autonomous Mode: DISABLED\n",
            },
            
            # MEMORY
            "memory_header": {
                "tr": "\n" + "=" * 60 + "\n🧠 AI HAFIZA DURUMU\n" + "=" * 60 + "\n",
                "en": "\n" + "=" * 60 + "\n🧠 AI MEMORY STATUS\n" + "=" * 60 + "\n",
            },
            
            "memory_summary": {
                "tr": """
Oturum Süresi: {duration}
Çalıştırılan Komutlar: {commands_executed}
Toplanan Bulgular: {findings_count}
Bulunan Zaafiyet: {vulnerabilities_count}
Taranılan Hedefler: {targets}
İstismarlar: {exploitations}
""",
                "en": """
Session Duration: {duration}
Commands Executed: {commands_executed}
Findings Collected: {findings_count}
Vulnerabilities Found: {vulnerabilities_count}
Targets Scanned: {targets}
Exploitations: {exploitations}
""",
            },
            
            # ERRORS
            "error_no_target": {
                "tr": "❌ Hedef belirtilmedi\n",
                "en": "❌ No target specified\n",
            },
            
            "error_not_understood": {
                "tr": "❌ Komutu anlamadım\n",
                "en": "❌ Command not understood\n",
            },
            
            # SUCCESS
            "success_shell": {
                "tr": "✅ Shell başarıyla alındı!\n",
                "en": "✅ Shell obtained successfully!\n",
            },
            
            "success_exploit": {
                "tr": "✅ Exploit başarılı!\n",
                "en": "✅ Exploit successful!\n",
            },
        }
    
    def get(self, key: str, lang: Language, **kwargs) -> str:
        """Get response in specified language"""
        if key not in self.responses:
            return f"[Missing response: {key}]"
        
        response_dict = self.responses[key]
        text = response_dict.get(lang, response_dict.get("en", ""))
        
        # Format with provided arguments
        try:
            return text.format(**kwargs)
        except KeyError:
            return text


class LocalizationManager:
    """Manage all localization and multi-language features"""
    
    def __init__(self):
        self.detector = LanguageDetector()
        self.responses = MultiLanguageResponses()
        self.user_language: Language = "en"  # Default
        self.session_language: Language = "en"
    
    def set_user_language(self, text: str):
        """Detect and set user language from their input"""
        self.user_language = self.detector.detect(text)
        self.session_language = self.user_language
        logger.info(f"[LANGUAGE] User language: {self.detector.get_language_name(self.user_language)}")
    
    def get_response(self, key: str, **kwargs) -> str:
        """Get response in user's language"""
        return self.responses.get(key, self.session_language, **kwargs)
    
    def get_in_language(self, key: str, lang: Language, **kwargs) -> str:
        """Get response in specific language"""
        return self.responses.get(key, lang, **kwargs)
    
    def format_menu(self, lang: Language) -> str:
        """Format menu in specified language"""
        if lang == "tr":
            return """
┌─────────────────────────────────────┐
│     🩸 DRAKBEN v5.0 - KOMUTLAR 🩸   │
├─────────────────────────────────────┤
│  🎯 TEMEL KOMUTLAR:                 │
│    target <IP>     → Hedef Ayarla   │
│    strategy <mod>  → Strateji Seç   │
│    scan            → Tarama Yap     │
│    exploit         → İstismar Yap   │
│    payload         → Payload Üret   │
│                                     │
│  🤖 AI ÖZERK MODU:                 │
│    auto_mode       → Mod Aç/Kapat  │
│    auto_pentest    → AI Pentest    │
│    ai_memory       → Hafızayı Göster│
│                                     │
│  💬 DIĞER:                          │
│    help            → Yardım         │
│    clear           → Ekranı Temizle│
│    exit            → Çıkış          │
│                                     │
└─────────────────────────────────────┘
"""
        else:  # English
            return """
┌─────────────────────────────────────┐
│     🩸 DRAKBEN v5.0 - COMMANDS 🩸   │
├─────────────────────────────────────┤
│  🎯 BASIC COMMANDS:                 │
│    target <IP>     → Set Target     │
│    strategy <mode> → Set Strategy   │
│    scan            → Run Scan       │
│    exploit         → Run Exploit    │
│    payload         → Generate       │
│                                     │
│  🤖 AI AUTONOMOUS:                  │
│    auto_mode       → Toggle Mode    │
│    auto_pentest    → AI Pentest     │
│    ai_memory       → Show Memory    │
│                                     │
│  💬 OTHER:                          │
│    help            → Show Help      │
│    clear           → Clear Screen   │
│    exit            → Exit           │
│                                     │
└─────────────────────────────────────┘
"""
