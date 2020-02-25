import pytest
import json
import mock

# from flask import current_app as app
from freezegun import freeze_time
from cookie_manager.cookie_manager import CookieManager
from werkzeug.exceptions import Unauthorized, HTTPException
from itsdangerous import TimestampSigner, BadSignature, SignatureExpired


class TestCookieManager:
    @freeze_time("2019-12-06")
    def test_decode_cookie_positive(self):
        cookie_value = json.dumps(
            {
                "client_id": "parent-management",
                "school_uuid": "5b5719cd-9099-469c-b05e-fd8da64ce367",
                "user_id": "ANYTHING",
            }
        )

        signed_cookie = (
            TimestampSigner(secret_key="test_key").sign(cookie_value).decode("utf8")
        )

        unsigned_cookie = CookieManager().decode_cookie(
            cookie=signed_cookie, verify_key="test_key"
        )

        assert unsigned_cookie == json.loads(cookie_value)

    # @freeze_time("2019-12-06")
    # def test_decode_cookie_bad_signature(self):
    #     cookie_value = json.dumps(
    #         {
    #             "client_id": "parent-management",
    #             "school_uuid": "5b5719cd-9099-469c-b05e-fd8da64ce367",
    #             "user_id": "ANYTHING",
    #         }
    #     )
    #
    #     signed_cookie = (
    #         TimestampSigner(secret_key="test_key").sign(cookie_value).decode("utf8")
    #     )
    #
    #     with pytest.raises(Unauthorized):
    #         result = CookieManager().decode_cookie(cookie=signed_cookie, verify_key="wrong_key")

    # @freeze_time("2019-12-06")
    # def test_decode_cookie_expired_signing(self):
    #     app.config["COOKIE_UNSIGN_MAX_AGE"] = 1
    #
    #     cookie_value = json.dumps(
    #         {
    #             "client_id": "parent-management",
    #             "school_uuid": "5b5719cd-9099-469c-b05e-fd8da64ce367",
    #             "user_id": "ANYTHING",
    #         }
    #     )
    #
    #     signed_cookie = (
    #         TimestampSigner(secret_key="test_key").sign(cookie_value).decode("utf8")
    #     )
    #
    #     with pytest.raises(Unauthorized):
    #         CookieManager().decode_cookie(
    #             cookie=f"{signed_cookie}.XemaAA.3N_BtXRXlZr1JUA-p6rNUwaCFTY",
    #             unsigning_key="test_key",
    #         )
    #
    # @freeze_time("2019-12-06")
    # def test_decode_cookie_empty_cookie(self):
    #     with pytest.raises(Unauthorized):
    #         CookieManager().decode_cookie(
    #             cookie="", unsigning_key="test_key",
    #         )
    #
    # @freeze_time("2019-12-06")
    # @mock.patch("json.loads")
    # def test_decode_cookie_invalid_json(self, mocked_json_loads):
    #     app.config["COOKIE_UNSIGN_MAX_AGE"] = 1
    #     mocked_json_loads.side_effect = ValueError
    #
    #     cookie_value = json.dumps(
    #         {
    #             "client_id": "parent-management",
    #             "school_uuid": "5b5719cd-9099-469c-b05e-fd8da64ce367",
    #             "user_id": "ANYTHING",
    #         }
    #     )
    #
    #     signed_cookie = (
    #         TimestampSigner(secret_key="test_key").sign(cookie_value).decode("utf8")
    #     )
    #
    #     result = CookieManager().decode_cookie(
    #         cookie=signed_cookie, unsigning_key="test_key",
    #     )
    #
    #     assert result is None
    #
    # @freeze_time("2019-12-06")
    # @mock.patch("itsdangerous.TimestampSigner.unsign")
    # def test_decode_cookie_general_error(self, mocked_timestamp_signer):
    #     app.config["COOKIE_UNSIGN_MAX_AGE"] = 1
    #     mocked_timestamp_signer.side_effect = KeyError  # Any error will do
    #
    #     cookie_value = json.dumps(
    #         {
    #             "client_id": "parent-management",
    #             "school_uuid": "5b5719cd-9099-469c-b05e-fd8da64ce367",
    #             "user_id": "ANYTHING",
    #         }
    #     )
    #
    #     signed_cookie = (
    #         TimestampSigner(secret_key="test_key").sign(cookie_value).decode("utf8")
    #     )
    #
    #     with pytest.raises(HTTPException):
    #         CookieManager().decode_cookie(
    #             cookie=signed_cookie, unsigning_key="test_key",
    #         )
    #
    # @freeze_time("2019-12-06")
    # def test_sign_cookie_positive(self):
    #     cookie_value = {
    #         "client_id": "parent-management",
    #         "school_uuid": "5b5719cd-9099-469c-b05e-fd8da64ce367",
    #         "user_id": "ANYTHING",
    #     }
    #
    #     signed_cookie = CookieManager().sign_cookie(
    #         cookie=cookie_value, signing_key="test_key"
    #     )
    #
    #     assert (
    #         signed_cookie
    #         == f"{json.dumps(cookie_value)}.XemaAA.3N_BtXRXlZr1JUA-p6rNUwaCFTY"
    #     )
    #
    # @freeze_time("2019-12-06")
    # @mock.patch("itsdangerous.TimestampSigner.sign")
    # def test_sign_cookie_signing_error(self, mocked_timestamp_signer_sign):
    #     mocked_timestamp_signer_sign.side_effect = KeyError  # Any error will do
    #     with pytest.raises(KeyError):
    #         CookieManager().sign_cookie(cookie={}, signing_key="test_key")
