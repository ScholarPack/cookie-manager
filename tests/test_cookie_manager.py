import pytest
import json
import mock

from freezegun import freeze_time
from cookie_manager.cookie_manager import CookieManager
from werkzeug import exceptions
from itsdangerous import TimestampSigner


class TestCookieManager:
    cookie_manager = None

    def setup_method(self):
        self.cookie_manager = CookieManager(keys={"A": "A"}, exceptions=exceptions)

    @freeze_time("2019-12-06")
    def test_verify_positive(self):
        cookie_value = json.dumps({"A": "B", "key_id": "A"})

        signed_cookie = (
            TimestampSigner(secret_key="A").sign(cookie_value).decode("utf8")
        )

        unsigned_cookie = self.cookie_manager.verify(signed_cookie=signed_cookie)

        assert unsigned_cookie == json.loads(cookie_value)

    @freeze_time("2019-12-06")
    def test_verify_nonexistent_keyid(self):
        cookie_value = json.dumps({"A": "B", "key_id": "C"})

        signed_cookie = (
            TimestampSigner(secret_key="A").sign(cookie_value).decode("utf8")
        )

        with pytest.raises(exceptions.ServiceUnavailable):
            self.cookie_manager.verify(signed_cookie=signed_cookie)

    @freeze_time("2019-12-06")
    def test_decode_verify_positive(self):
        cookie_value = json.dumps({"A": "B"})

        signed_cookie = (
            TimestampSigner(secret_key="test_key").sign(cookie_value).decode("utf8")
        )

        unsigned_cookie = self.cookie_manager._decode_verify_cookie(
            cookie=signed_cookie, verify_key="test_key"
        )

        assert unsigned_cookie == json.loads(cookie_value)

    @freeze_time("2019-12-06")
    def test_decode_verify_empty_cookie(self):
        with pytest.raises(exceptions.Unauthorized):
            self.cookie_manager._decode_verify_cookie(
                cookie="", verify_key="test_key",
            )

    @freeze_time("2019-12-06")
    def test_decode_verify_bad_signature(self):
        cookie_value = json.dumps({"A": "B",})

        signed_cookie = (
            TimestampSigner(secret_key="test_key").sign(cookie_value).decode("utf8")
        )

        with pytest.raises(exceptions.Unauthorized):
            self.cookie_manager._decode_verify_cookie(
                cookie=signed_cookie, verify_key="wrong_key"
            )

    @freeze_time("2019-12-06")
    def test_decode_verify_expired_signature(self):
        cookie_value = json.dumps({"A": "B"})

        signed_cookie = (
            TimestampSigner(secret_key="test_key").sign(cookie_value).decode("utf8")
        )

        with pytest.raises(exceptions.Unauthorized):
            self.cookie_manager._decode_verify_cookie(
                cookie=f"{signed_cookie}.XemaAA.3N_BtXRXlZr1JUA-p6rNUwaCFTY",
                verify_key="test_key",
            )

    @freeze_time("2019-12-06")
    @mock.patch("itsdangerous.TimestampSigner.unsign")
    def test_decode_verify_general_error(self, mocked_timestamp_signer):
        mocked_timestamp_signer.side_effect = KeyError  # Any error will do

        cookie_value = json.dumps({"A": "B"})

        signed_cookie = (
            TimestampSigner(secret_key="test_key").sign(cookie_value).decode("utf8")
        )

        with pytest.raises(exceptions.HTTPException):
            self.cookie_manager._decode_verify_cookie(
                cookie=signed_cookie, verify_key="test_key",
            )

    @freeze_time("2019-12-06")
    @mock.patch("json.loads")
    def test_decode_verify_invalid_json(self, mocked_json_loads):
        mocked_json_loads.side_effect = ValueError

        cookie_value = json.dumps({"A": "B"})

        signed_cookie = (
            TimestampSigner(secret_key="test_key").sign(cookie_value).decode("utf8")
        )

        result = self.cookie_manager._decode_verify_cookie(
            cookie=signed_cookie, verify_key="test_key",
        )

        assert result is None

    @freeze_time("2019-12-06 14:22:00")
    def test_sign_cookie_positive(self):
        cookie_value = {"A": "B"}

        signed_cookie = self.cookie_manager._sign_cookie(
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
        with pytest.raises(exceptions.ServiceUnavailable):
            self.cookie_manager._sign_cookie(cookie={}, signing_key="test_key")

    @pytest.mark.parametrize(
        "input_,expected_output",
        [
            ({"A": "1", "B": "B", "C": "C"}, {"A": "1", "B": "B", "C": "C"}),
            ({"A": "1"}, {"A": "1", "B": "B", "C": "C"}),
            (None, {"A": "A", "B": "B", "C": "C"}),
            ({}, {"A": "A", "B": "B", "C": "C"}),
        ],
    )
    def test_override_config_positive(self, input_, expected_output):
        self.cookie_manager._config = {"A": "A", "B": "B", "C": "C"}
        result = self.cookie_manager._override_config(override_config=input_)
        assert result == expected_output

    def test_override_config_negative(self):
        self.cookie_manager._config = {"A": "A", "B": "B", "C": "C"}
        bad_override_config = {"D": "D"}

        with pytest.raises(exceptions.BadRequest):
            self.cookie_manager._override_config(override_config=bad_override_config)

    @pytest.mark.parametrize(
        "input_,expected_output",
        [
            (
                '{"A": "B", "key_id": "test_key_id"}.XepkCA.CUZtVTCXHbqoalWVCh5xOa4S4WE',
                "test_key_id",
            ),
            ('{"A": "B"}.XepkCA.CUZtVTCXHbqoalWVCh5xOa4S4WE', None),
        ],
    )
    def test_extract_key_id_positive(self, input_, expected_output):
        result = self.cookie_manager._extract_key_id(signed_cookie=input_)
        assert result == expected_output

    @pytest.mark.parametrize(
        "input_,error",
        [
            ("RANDOM_BLAH", exceptions.Unauthorized),
            ("RANDOM_BLAH}", exceptions.Unauthorized),
        ],
    )
    def test_extract_key_id_negative(self, input_, error):
        with pytest.raises(error):
            self.cookie_manager._extract_key_id(signed_cookie=input_)

    @freeze_time("2019-12-06 14:22:00")
    def test_sign_positive(self):
        cookie_value = {"A": "B"}
        self.cookie_manager._keys = {"key_id": "test_key"}
        signed_cookie = self.cookie_manager.sign(cookie=cookie_value, key_id="key_id")

        assert (
            signed_cookie
            == f"{json.dumps(cookie_value)}.XepkCA.S6GGQPTUJw4MWDLvvyZhwcMZ1W8"
        )

    @freeze_time("2019-12-06 14:22:00")
    def test_sign_negative(self):
        cookie_value = {"A": "B"}

        with pytest.raises(exceptions.ServiceUnavailable):
            self.cookie_manager.keys = {"C": "D"}
            self.cookie_manager.sign(cookie=cookie_value, key_id="bad_key")
