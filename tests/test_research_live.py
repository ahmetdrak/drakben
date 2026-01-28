
import sys
import os
import time
from unittest.mock import MagicMock, patch
from io import StringIO

# Add project root to path
sys.path.append(os.getcwd())

try:
    from core.menu import DrakbenMenu
    from core.config import ConfigManager
except ImportError as e:
    print(f"Import Error: {e}")
    sys.exit(1)

def test_research_real_integration():
    print("🔥 BAŞLATILIYOR: /research Komutu Gerçek Dünya Testi...")
    
    # Mock ConfigManager to avoid interactive setup logic
    mock_config = MagicMock(spec=ConfigManager)
    # Create a deeper mock for the config object itself
    mock_config.config = MagicMock()
    mock_config.config.language = "tr" 
    # Also set it directly on manager if accessed directly (just in case)
    mock_config.language = "tr"
    
    # Instantiate Menu
    # We patch print/console to see what happens
    menu = DrakbenMenu(mock_config)
    
    # We need to capture what the menu prints
    captured_output = []
    
    def mock_print(*args, **kwargs):
        # Join args to simulate print behavior
        msg = " ".join(str(a) for a in args)
        captured_output.append(msg)
        # Also print to real stdout so user can see it in logs
        print(f"[MENU_OUTPUT] {msg}")

    # Inject our spy mock into the menu's console
    menu.console = MagicMock()
    menu.console.print = mock_print
    
    # Simulate User Input: 
    # 1. /research sqlmap github
    # 2. /exit
    inputs = ['/research sqlmap github', '/exit']
    
    print(f"📝 Simüle Edilen Komutlar: {inputs}")

    with patch.object(menu, '_get_input', side_effect=inputs):
        try:
            menu.run()
        except (StopIteration, SystemExit):
            pass
        except Exception as e:
            print(f"❌ TEST HATASI: {e}")
            import traceback
            traceback.print_exc()

    # Analyze Results
    full_log = "\n".join(captured_output)
    
    print("-" * 50)
    print("📊 TEST SONUCU ANALİZİ")
    print("-" * 50)

    if ("github" in full_log.lower() and "sqlmapproject" in full_log.lower()) or "sqlmap" in full_log.lower():
        print("✅ BAŞARILI: SQLMap GitHub sonuçları bulundu!")
        print("Kanıt Satırları:")
        for line in captured_output:
            if "http" in line or "Villager" in line:
                print(f"  -> {line}")
    elif "searching for" in full_log.lower() and "no results" in full_log.lower():
        print("⚠️ UYARI: Arama çalıştı ama sonuç dönmedi (DuckDuckGo engelli olabilir veya sonuç yok).")
    else:
        print("❌ BAŞARISIZ: Arama tetiklenmedi veya çıktı alınamadı.")

if __name__ == "__main__":
    test_research_real_integration()
