import datetime
import logging
from functools import wraps

import redis
from flask import redirect, url_for

from config.config import config

redis_conn = redis.Redis(host=config.REDIS_HOST, port=6379, db=0)
log = logging.getLogger(__name__)


def circuitbreakers(exeption=Exception, fail_max=5, reset_timeout=60, redirect_to='auth.login'):
    """Если при запросе возникает ошибка, то делает перенаправление.
    После fail_max запросов перестает отправлять запросы
    и делает сразу перенаправлениие в течении reset_timeout"""

    def breaker(fn):
        @wraps(fn)
        def wrapper(*arg, **kwargs):
            try:
                pipe = redis_conn.pipeline()
                now = datetime.datetime.now()
                key = f'{exeption}:{now.minute}'
                c = pipe.get(key)
                result = pipe.execute()
                request_number = result[0] if result is not None else 0
                if int(request_number) > fail_max:
                    return redirect(url_for(redirect_to))
                fn(*arg, **kwargs)
            except:
                log.warning(str(exeption))
                now = datetime.datetime.now()
                key = f'{exeption}:{now.minute}'
                pipe.incr(key, 1)
                pipe.expire(key, reset_timeout)
                pipe.execute()
                return redirect(url_for(redirect_to))

        return wrapper

    return breaker
