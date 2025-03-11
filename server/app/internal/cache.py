import valkey.asyncio as valkey
from .config import settings


v = valkey.Valkey.from_url(str(settings.VALKEY_URI))
