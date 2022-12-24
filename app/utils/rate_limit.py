import datetime
from functools import wraps

import redis
from flask import jsonify, request

from config.config import config

# Установим лимит запросов в минуту
REQUEST_LIMIT_PER_MINUTE = config.REQUEST_LIMIT_PER_MINUTE

redis_conn = redis.Redis(host='localhost', port=6379, db=0)


def ratelimit(per_min=REQUEST_LIMIT_PER_MINUTE):
    """ Ограничение количества запрос с 1 IP в мин"""

    def limit(fn):
        @wraps(fn)
        def wrapper(*arg, **kwargs):
            ip = request.remote_addr
            pipe = redis_conn.pipeline()
            now = datetime.datetime.now()
            key = f'{ip}:{now.minute}'
            pipe.incr(key, 1)
            pipe.expire(key, 59)
            result = pipe.execute()
            request_number = result[0]
            if request_number > per_min:
                return jsonify(Error=f"Your ip='{ip}' is blocked")
            else:
                return fn(*arg, **kwargs)

        return wrapper

    return limit


def check_ip(ip):
    pipe = redis_conn.pipeline()
    now = datetime.datetime.now()
    key = f'{ip}:{now.minute}'
    pipe.incr(key, 1)
    pipe.expire(key, 59)
    result = pipe.execute()
    request_number = result[0]
    if request_number > REQUEST_LIMIT_PER_MINUTE:
        return False
    else:
        return True
