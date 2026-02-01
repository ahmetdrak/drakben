# core/i18n.py
# DRAKBEN Internationalization - Turkish/English Language Support


DEFAULT_LANG = "tr"

TRANSLATIONS: dict[str, dict[str, str]] = {
    "tr": {
        # General
        "app_name": "DRAKBEN",
        "welcome": "DRAKBEN Pentest AI Asistanına Hoşgeldiniz",
        "version": "Versiyon",
        "language": "Dil",
        "target": "Hedef",
        "prompt": "drakben> ",
        # States
        "thinking": "Düşünüyor",
        "analyzing": "Analiz ediliyor",
        "executing": "Çalıştırılıyor",
        "scanning": "Taranıyor",
        "processing": "İşleniyor",
        # Results
        "success": "Başarılı",
        "failed": "Başarısız",
        "error": "Hata",
        "warning": "Uyarı",
        # Settings
        "target_set": "Hedef ayarlandı",
        "lang_set": "Dil ayarlandı",
        "not_set": "Ayarlanmadı",
        "status": "Durum",
        # Help
        "help_title": "Yardım",
        "help_commands": "Komutlar",
        "help_examples": "Örnekler",
        # Messages
        "no_command_generated": "Komut üretilemedi. Lütfen daha spesifik olun.",
        "interrupted": "İşlem iptal edildi",
        "goodbye": "Görüşürüz!",
        "thanks": "DRAKBEN'i kullandığınız için teşekkürler.",
        "need_target": "Lütfen önce bir hedef belirleyin: /target <IP>",
        "unknown_command": "Bilinmeyen komut",
        # Scanning
        "starting_scan": "Tarama başlatılıyor",
        "scan_complete": "Tarama tamamlandı",
        "ports_found": "açık port bulundu",
        "vulnerabilities_found": "zafiyet bulundu",
        # AI
        "ai_thinking": "AI düşünüyor",
        "ai_response": "AI yanıtı",
        "generating_command": "Komut oluşturuluyor",
        # Approval
        "approve_command": "Bu komutu çalıştırmak ister misiniz?",
        "approved": "Onaylandı",
        "denied": "Reddedildi",
        # Sistem
        "system_info": "Sistem Bilgisi",
        "tools_available": "Mevcut Araçlar",
        "kali_detected": "Kali Linux algılandı",
        # Autonomous loop
        "starting_autonomous": "Otonom döngü başlatılıyor",
        "phase_transition": "Faz geçişi",
        "iteration": "İterasyon",
    },
    "en": {
        # General
        "app_name": "DRAKBEN",
        "welcome": "Welcome to DRAKBEN Pentest AI Assistant",
        "version": "Version",
        "language": "Language",
        "target": "Target",
        "prompt": "drakben> ",
        # States
        "thinking": "Thinking",
        "analyzing": "Analyzing",
        "executing": "Executing",
        "scanning": "Scanning",
        "processing": "Processing",
        # Results
        "success": "Success",
        "failed": "Failed",
        "error": "Error",
        "warning": "Warning",
        # Settings
        "target_set": "Target set",
        "lang_set": "Language set",
        "not_set": "Not set",
        "status": "Status",
        # Help
        "help_title": "Help",
        "help_commands": "Commands",
        "help_examples": "Examples",
        # Messages
        "no_command_generated": "Could not generate command. Please be more specific.",
        "interrupted": "Operation cancelled",
        "goodbye": "Goodbye!",
        "thanks": "Thanks for using DRAKBEN.",
        "need_target": "Please set a target first: /target <IP>",
        "unknown_command": "Unknown command",
        # Scanning
        "starting_scan": "Starting scan",
        "scan_complete": "Scan complete",
        "ports_found": "open ports found",
        "vulnerabilities_found": "vulnerabilities found",
        # AI
        "ai_thinking": "AI thinking",
        "ai_response": "AI response",
        "generating_command": "Generating command",
        # Approval
        "approve_command": "Run this command?",
        "approved": "Approved",
        "denied": "Denied",
        # System
        "system_info": "System Info",
        "tools_available": "Available Tools",
        "kali_detected": "Kali Linux detected",
        # Autonomous loop
        "starting_autonomous": "Starting autonomous loop",
        "phase_transition": "Phase transition",
        "iteration": "Iteration",
    },
}


def t(key: str, lang: str = DEFAULT_LANG) -> str:
    """Çeviri al"""
    lang_map = TRANSLATIONS.get(lang, TRANSLATIONS[DEFAULT_LANG])
    return lang_map.get(key, key)


def get_language_name(lang: str) -> str:
    """Dil adını al"""
    names = {"tr": "Türkçe", "en": "English"}
    return names.get(lang, lang)


def get_available_languages() -> list:
    """Mevcut dilleri listele"""
    return list(TRANSLATIONS.keys())
