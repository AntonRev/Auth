import logging.config

import backoff
from redis import Redis
from redis.exceptions import ConnectionError

from config.config import config
from config.logger import LOGGING

logging.config.dictConfig(LOGGING)
log = logging.getLogger('__name__')


@backoff.on_exception(backoff.expo,
                      ConnectionError,
                      max_time=60)
def conn_redis():
    r = Redis(config.REDIS_HOST)
    r.ping()
    log.info("Redis connected")


if __name__ == '__main__':
    log.info("Waiting start Redis")
    conn_redis()
