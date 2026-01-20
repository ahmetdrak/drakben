from typing import Dict


DEFAULT_LANG = "tr"

TRANSLATIONS: Dict[str, Dict[str, str]] = {
    "tr": {
        "app_name": "DRAKBEN",
        "welcome": "DRAKBEN Pentest AI Asistanına Hoşgeldiniz",
        "version": "Versiyon",
        "language": "Dil",
        "target": "Hedef",
        "prompt": "drakben> ",
        "thinking": "Düşünüyor",
        "analyzing": "Analiz ediliyor",
        "executing": "Çalıştırılıyor",
        "success": "Başarılı",
        "failed": "Başarısız",
        "target_set": "Hedef ayarlandı",
        "lang_set": "Dil ayarlandı",
        "not_set": "Ayarlanmadı",
        "status": "Durum",
        "help_title": "Yardım",
        "no_command_generated": "Komut üretilemedi. Lütfen daha spesifik olun.",
        "interrupted": "İşlem iptal edildi",
        "goodbye": "Görüşürüz!",
        "thanks": "DRAKBEN'i kullandığınız için teşekkürler.",
        "need_target": "Lütfen önce bir hedef belirleyin: target <IP>",
    },
    "en": {
        "app_name": "DRAKBEN",
        "welcome": "Welcome to DRAKBEN Pentest AI Assistant",
        "version": "Version",
        "language": "Language",
        "target": "Target",
        "prompt": "drakben> ",
        "thinking": "Thinking",
        "analyzing": "Analyzing",
        "executing": "Executing",
        "success": "Success",
        "failed": "Failed",
        "target_set": "Target set",
        "lang_set": "Language set",
        "not_set": "Not set",
        "status": "Status",
        "help_title": "Help",
        "no_command_generated": "Could not generate command. Please be more specific.",
        "interrupted": "Operation cancelled",
        "goodbye": "Goodbye!",
        "thanks": "Thanks for using DRAKBEN.",
        "need_target": "Please set a target first: target <IP>",
    }
}


def t(key: str, lang: str) -> str:
    lang_map = TRANSLATIONS.get(lang, TRANSLATIONS[DEFAULT_LANG])
    return lang_map.get(key, key)
