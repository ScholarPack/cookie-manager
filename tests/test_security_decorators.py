import pytest
from cookie_manager import CookieManager, CookieSecurityDecorator
from werkzeug import exceptions
from typing import List, Any


class FakeRequest:
    cookies = {}


class TestSecurityDecorators:
    def setup_method(self):
        self.keys = {
            "A": "A",
            "B": "B",
            "C": "C",
            "D": "D",
        }
        self.cookie_data = {"data": ""}
        self.cookie_manager = CookieManager(
            keys=self.keys,
            exceptions=exceptions,
        )
        self.decorator = CookieSecurityDecorator()

    def decorator_runner(
        self,
        request_object: Any,
        cookie_manager: CookieManager,
        enabled_keys: List = [],
    ):
        self.decorator.init_app(
            request=request_object,
            cookie_manager=cookie_manager,
            cookie_name="test_cookie",
        )

        @self.decorator.keys_required(enabled_keys)
        def sample_route():
            return True

        return sample_route()

    def create_request(self, key_id: str):
        cookie_value = {"test": ""}
        signed_cookie = self.cookie_manager.sign(cookie=cookie_value, key_id=key_id)
        request = FakeRequest()
        request.cookies = {"test_cookie": signed_cookie}
        return request

    def test_restricted_route(self):
        assert True == self.decorator_runner(
            request_object=self.create_request("A"), cookie_manager=self.cookie_manager
        )

    def test_specifically_restricted_route(self):
        allowed_keys = ["A"]
        assert True == self.decorator_runner(
            request_object=self.create_request("A"),
            enabled_keys=allowed_keys,
            cookie_manager=self.cookie_manager,
        )

        allowed_keys = ["A", "B", "C", "D"]
        assert True == self.decorator_runner(
            request_object=self.create_request("D"),
            enabled_keys=allowed_keys,
            cookie_manager=self.cookie_manager,
        )

    def test_disallowed_route(self):
        allowed_keys = ["B"]
        with pytest.raises(exceptions.Unauthorized):
            self.decorator_runner(
                request_object=self.create_request("A"),
                enabled_keys=allowed_keys,
                cookie_manager=self.cookie_manager,
            )
