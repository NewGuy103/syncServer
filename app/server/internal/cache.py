import logging
import asyncio

import valkey.asyncio as valkey
from .config import settings


logger: logging.Logger = logging.getLogger("syncserver")


# TODO: Implement a generic cache provider to make valkey optional
class CacheProvider:
    def __init__(self):
        self.valkey = None
        self._local_locks: dict[str, asyncio.Lock] = {}
        
        self._data: dict = {}

    async def setup(self) -> valkey.Valkey | None:
        if not settings.USE_VALKEY_CACHE:
            logger.warning("Valkey disabled from environment configuration")
            return None
        
        self.valkey = valkey.Valkey.from_url(str(settings.VALKEY_URI))
        return self.valkey
    
    def lock(self, key: str):
        if self.valkey is None:
            local_lock = self._local_locks.get(key)

            if local_lock:
                return local_lock
            
            lock = asyncio.Lock()
            self._local_locks[key] = lock

            return lock
        
        valkey_lock = self.valkey.lock(key, blocking=True)
        return valkey_lock
    
    async def set(self, key: str, value: str):
        """Simple key-value setting, as a fallback if valkey is not used."""
        self._data[key] = value
    
    async def get(self, key: str):
        """Simple key-value setting, as a fallback if valkey is not used."""
        return self._data.get(key, None)


cache = CacheProvider()
