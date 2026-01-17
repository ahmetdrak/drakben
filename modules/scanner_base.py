# modules/scanner_base.py

import asyncio

async def run_module_async(func, *args, **kwargs):
    try:
        print(f"[scanner_base] {func.__name__} çalıştırılıyor...")
        
        if asyncio.iscoroutinefunction(func):
            # Eğer fonksiyon async ise doğrudan await et
            return await func(*args, **kwargs)
        else:
            # Sync fonksiyonları ayrı thread'de çalıştır
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, lambda: func(*args, **kwargs))
    
    except Exception as e:
        print(f"[scanner_base] Hata: {e}")
        return {"error": str(e)}
