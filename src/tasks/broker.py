from taskiq_redis import ListQueueBroker
from src.core.config import settings

broker = ListQueueBroker(
    url=settings.REDIS_URL
)