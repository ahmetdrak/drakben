# modules/memory.py
# Drakben Memory Modülü - İleri Seviye Oturum Hafızası

import uuid
import datetime

class DrakbenMemory:
    def __init__(self):
        # Session ID oluştur
        self.session_id = str(uuid.uuid4())
        self.created_at = datetime.datetime.utcnow()
        self.data = {
            "recon": None,
            "exploit": None,
            "payload": None,
            "report": None,
            "notes": []
        }

    def save_recon(self, recon_result):
        print("[Memory] Recon sonucu kaydedildi.")
        self.data["recon"] = recon_result

    def save_exploit(self, exploit_result):
        print("[Memory] Exploit sonucu kaydedildi.")
        self.data["exploit"] = exploit_result

    def save_payload(self, payload_result):
        print("[Memory] Payload sonucu kaydedildi.")
        self.data["payload"] = payload_result

    def save_report(self, report_result):
        print("[Memory] Report sonucu kaydedildi.")
        self.data["report"] = report_result

    def add_note(self, note):
        print(f"[Memory] Not eklendi: {note}")
        self.data["notes"].append({
            "timestamp": str(datetime.datetime.utcnow()),
            "note": note
        })

    def get_session_summary(self):
        return {
            "session_id": self.session_id,
            "created_at": str(self.created_at),
            "data": self.data
        }

# Global memory instance
memory_instance = DrakbenMemory()

# Alias for compatibility
WorkingMemory = DrakbenMemory
