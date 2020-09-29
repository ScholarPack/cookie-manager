from functools import wraps
from typing import List, Any
from cookie_manager import CookieManager


class CookieSecurityDecorator:
    _cookie_manager = None
    _request = None
    _cookie_name = None

    def init_app(self, request: Any, cookie_manager: CookieManager, cookie_name: str):
        """
        Initialise the security decorators
        :param request: An object with the attribute `cookies`
        :param cookie_manager: The instance of the cookie manager to be used for the decorator
        :param cookie_name: The name of the cookie to read from the request
        """
        self._request = request
        self._cookie_manager = cookie_manager
        self._cookie_name = cookie_name

    def keys_required(self, keys: List = []):
        """
        :param keys: A list of cookie signing keys that are allowed to use a decorated endpoint.
        :raises Unauthorized: When the route is accessed without a valid key id
        :return: wrapper
        """

        def route_wrapper(f):
            @wraps(f)
            def wrapper(*args, **kwds):
                verfied_cookie = self._cookie_manager.verify(
                    signed_cookie=self._request.cookies.get(self._cookie_name)
                )

                key_id = verfied_cookie.get("key_id")
                if len(keys) == 0 or key_id in keys:
                    return f(*args, **kwds)
                else:
                    raise self._cookie_manager._exceptions.Unauthorized()

            return wrapper

        return route_wrapper
