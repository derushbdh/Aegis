from src.bot.handlers.common import router as common_router
from src.bot.handlers.scan import router as scan_router
from src.bot.handlers.history import router as history_router


__all__ = [
    "common_router",
    "scan_router",
    "history_router"
]