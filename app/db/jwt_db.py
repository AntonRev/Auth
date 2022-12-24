import redis

from config.config import config

jwt_db = redis.StrictRedis(host=config.REDIS_HOST,
                           port=config.REDIS_PORT,
                           db=0,
                           decode_responses=True
                           )
