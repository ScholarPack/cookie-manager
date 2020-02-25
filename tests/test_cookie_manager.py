import pytest
import json
import mock

# from flask import current_app as app
from freezegun import freeze_time
from cookie_manager.cookie_manager import CookieManager
from werkzeug.exceptions import Unauthorized, HTTPException, ServiceUnavailable
from itsdangerous import TimestampSigner, BadSignature, SignatureExpired


class TestCookieManager:
    @freeze_time("2019-12-06")
    def test_decode_cookie_positive(self):
        cookie_value = json.dumps({"A": "B"})

        signed_cookie = (
            TimestampSigner(secret_key="test_key").sign(cookie_value).decode("utf8")
        )

        unsigned_cookie = CookieManager().decode_cookie(
            cookie=signed_cookie, verify_key="test_key"
        )

        assert unsigned_cookie == json.loads(cookie_value)

    @freeze_time("2019-12-06")
    def test_decode_cookie_bad_signature(self):
        cookie_value = json.dumps({"A": "B",})

        signed_cookie = (
            TimestampSigner(secret_key="test_key").sign(cookie_value).decode("utf8")
        )

        with pytest.raises(Unauthorized):
            result = CookieManager().decode_cookie(
                cookie=signed_cookie, verify_key="wrong_key"
            )

    @freeze_time("2019-12-06")
    def test_decode_cookie_expired_signing(self):
        cookie_value = json.dumps({"A": "B"})

        signed_cookie = (
            TimestampSigner(secret_key="test_key").sign(cookie_value).decode("utf8")
        )

        with pytest.raises(Unauthorized):
            CookieManager().decode_cookie(
                cookie=f"{signed_cookie}.XemaAA.3N_BtXRXlZr1JUA-p6rNUwaCFTY",
                verify_key="test_key",
            )

    @freeze_time("2019-12-06")
    def test_decode_cookie_empty_cookie(self):
        with pytest.raises(Unauthorized):
            CookieManager().decode_cookie(
                cookie="", verify_key="test_key",
            )

    @freeze_time("2019-12-06")
    @mock.patch("json.loads")
    def test_decode_cookie_invalid_json(self, mocked_json_loads):
        mocked_json_loads.side_effect = ValueError

        cookie_value = json.dumps({"A": "B"})

        signed_cookie = (
            TimestampSigner(secret_key="test_key").sign(cookie_value).decode("utf8")
        )

        result = CookieManager().decode_cookie(
            cookie=signed_cookie, verify_key="test_key",
        )

        assert result is None

    @freeze_time("2019-12-06")
    @mock.patch("itsdangerous.TimestampSigner.unsign")
    def test_decode_cookie_general_error(self, mocked_timestamp_signer):
        mocked_timestamp_signer.side_effect = KeyError  # Any error will do

        cookie_value = json.dumps({"A": "B"})

        signed_cookie = (
            TimestampSigner(secret_key="test_key").sign(cookie_value).decode("utf8")
        )

        with pytest.raises(HTTPException):
            CookieManager().decode_cookie(
                cookie=signed_cookie, verify_key="test_key",
            )

    @freeze_time("2019-12-06 14:22:00")
    def test_sign_cookie_positive(self):
        cookie_value = {"A": "B"}

        signed_cookie = CookieManager().sign_cookie(
            cookie=cookie_value, signing_key="test_key"
        )

        assert (
            signed_cookie
            == f"{json.dumps(cookie_value)}.XepkCA.CUZtVTCXHbqoalWVCh5xOa4S4WE"
        )

    @freeze_time("2019-12-06")
    @mock.patch("itsdangerous.TimestampSigner.sign")
    def test_sign_cookie_signing_error(self, mocked_timestamp_signer_sign):
        mocked_timestamp_signer_sign.side_effect = KeyError  # Any error will do
        with pytest.raises(ServiceUnavailable):
            CookieManager().sign_cookie(cookie={}, signing_key="test_key")
