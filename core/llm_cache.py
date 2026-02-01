import hashlib
import logging
import sqlite3
import time

logger = logging.getLogger(__name__)


class LLMCache:
    """
    LLM Önbellekleme Sistemi
    ------------------------
    Amaç: Tekrar eden LLM sorgularını önbelleğe alarak hız ve maliyet avantajı sağlamak.
    Özellikler:
    - SQLite tabanlı kalıcı depolama
    - Sorgu hash'leme ile hızlı arama
    - TTL (Time-To-Live) desteği (varsayılan 24 saat)
    - Thread-safe yapı
    """

    def __init__(self, db_path: str = "llm_cache.db", ttl_seconds: int = 86400):
        self.db_path = db_path
        self.ttl_seconds = ttl_seconds
        self._init_db()

    def _init_db(self):
        """Veritabanı tablosunu oluştur"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS llm_cache (
                        query_hash TEXT PRIMARY KEY,
                        prompt TEXT NOT NULL,
                        response TEXT NOT NULL,
                        timestamp REAL NOT NULL
                    )
                """)
                # Performans için indeks (zaten PK indexli ama timestamp temizliği için iyi olabilir)
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_timestamp ON llm_cache(timestamp)"
                )
        except Exception as e:
            logger.error(f"Cache init error: {e}")

    def get(self, query: str) -> str | None:
        """
        Önbellekten yanıt getir

        Args:
            query: Kullanıcı sorgusu ve sistem promptunun birleşimi (benzersiz anahtar için)

        Returns:
            Önbellekteki yanıt veya None
        """
        query_hash = self._hash_query(query)

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT response, timestamp FROM llm_cache WHERE query_hash = ?",
                    (query_hash,),
                )
                row = cursor.fetchone()

                if row:
                    response, timestamp = row
                    # TTL Kontrolü
                    if time.time() - timestamp < self.ttl_seconds:
                        logger.debug(f"Cache HIT for query hash: {query_hash[:8]}")
                        return response
                    else:
                        logger.debug(f"Cache EXPIRED for query hash: {query_hash[:8]}")
                        # Süresi dolmuş kaydı temizle (isteğe bağlı, sonraki set zaten ezecek)
                        return None
        except Exception as e:
            logger.error(f"Cache read error: {e}")
            return None

        logger.debug(f"Cache MISS for query hash: {query_hash[:8]}")
        return None

    def set(self, query: str, response: str):
        """
        Yanıtı önbelleğe kaydet

        Args:
            query: Sorgu metni
            response: LLM yanıtı
        """
        query_hash = self._hash_query(query)
        timestamp = time.time()
        # SECURITY: Do not cache query/response with sensitive keywords
        sensitive_keywords = [
            "password",
            "key",
            "token",
            "secret",
            "credential",
            "auth",
        ]
        if any(k in query.lower() for k in sensitive_keywords) or any(
            k in response.lower() for k in sensitive_keywords
        ):
            return

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO llm_cache (query_hash, prompt, response, timestamp) VALUES (?, ?, ?, ?)",
                    (query_hash, query, response, timestamp),
                )
            logger.debug(f"Cache SET for query hash: {query_hash[:8]}")
        except Exception as e:
            logger.error(f"Cache write error: {e}")

    @staticmethod
    def _hash_query(query: str) -> str:
        """Sorguyu MD5 ile hashle"""
        return hashlib.md5(query.encode("utf-8")).hexdigest()

    def clear_expired(self):
        """Süresi dolmuş kayıtları temizle"""
        expiration_cutoff = time.time() - self.ttl_seconds
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "DELETE FROM llm_cache WHERE timestamp < ?", (expiration_cutoff,)
                )
        except Exception as e:
            logger.error(f"Cache cleanup error: {e}")
