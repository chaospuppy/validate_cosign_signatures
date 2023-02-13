import functools
import requests

from ironbank.pipeline.utils import logger

class MaxRetriesException(Exception):
    pass

log = logger.setup("retry")

def request_retry(retry_count):
    """
    Decorator for retrying a function running a subprocess call
    """

    def decorate(func):
        # args and kwargs are passed to allow this decorator to work on any method
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            for retry_num in range(1, retry_count + 1):
                try:
                    return func(*args, **kwargs)
                except requests.HTTPError:
                    if retry_num >= retry_count:
                        # prevent exception chaining by using from None
                        raise MaxRetriesException() from None
                    log.warning("Request failed, retrying...")

        return wrapper

    return decorate

