from functools import wraps

from flask import request
from opentelemetry import trace


def tracer(fn):
    @wraps(fn)
    def wrapper(*arg, **kwargs):
        request_id = request.headers.get('Request-Id')
        tracer = trace.get_tracer(__name__)
        span = tracer.start_span(fn.__name__)
        span.set_attribute('http.request_id', request_id)
        fn(*arg, **kwargs)
        span.end()

    return wrapper
