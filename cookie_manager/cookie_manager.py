import json
import re

from itsdangerous import TimestampSigner, BadSignature, SignatureExpired
from werkzeug.exceptions import Unauthorized, ServiceUnavailable, BadRequest


class CookieManager:
    _config: dict = {
        "VERIFY_MAX_COOKIE_AGE": 50,  # Cookie TTL in seconds (enforced when verifying, not when signing)
    }
    _logger = type(
        "logger",
        (),
        {
            "error": lambda msg: print(msg),
            "warning": lambda msg: print(msg),
            "debug": lambda msg: print(msg),
            "info": lambda msg: print(msg),
        },
    )

    def __init__(self, config: dict = None, logger=None) -> None:
        self._logger.info(f"Configuring cookie manager")
        if config:
            self._config = self._ratify_config(override_config=config)
        if logger:
            self._logger = logger
        self._logger.info(f"Finished configuring cookie manager")

    def _ratify_config(self, override_config: dict) -> dict:
        """
        Takes a config dict ``override_config`` and overrides any default values found in ``self._config``
        Will error out if a config element does not exist in the parent dict
        :param override_config: Dict of config options
        :return: copy of ``self._config`` dict with values updated by those supplied in ``override_config``
        """
        self._logger.info(f"Starting to compare config: {override_config}")
        new_config: dict = self._config

        if override_config:
            self._logger.debug("Override config provided")
            for key, value in override_config.items():
                self._logger.debug(f"Comparing config entry: {key} - {value}")
                try:
                    # Only override existing values
                    new_config[key]
                except KeyError:
                    self._logger.error(f"Refusing to override config: {key} - {value}")
                    raise BadRequest
                new_config[key] = value

        self._logger.info(f"Finished comparing config: {override_config}")
        return new_config

    def decode_cookie(self, cookie: str, verify_key: str) -> [None, dict]:
        """
        Verify and decode a signed cookie payload from other internal services.
        Will trigger ``self.failure_func`` with a http status code upon error
        Logs status to ``self.logger``
        :param cookie: Signed payload for one cookie
        :param verify_key: Str used to verify original signer of cookie
        :return: Verified cookie dict payload, None,
        """
        self._logger.info(f"Starting to verify cookie: {cookie}")

        if cookie is None:
            self._logger.warning(f"Incoming cookie '{cookie}' not provided.")
            raise Unauthorized
        try:
            self._logger.debug(f"Beginning verification: {cookie}")
            cookie_value_json = TimestampSigner(verify_key).unsign(
                value=cookie, max_age=self._config.get("VERIFY_MAX_COOKIE_AGE", 50)
            )
        except BadSignature as e:
            self._logger.warning(
                f"Incoming cookie payload: '{cookie}' failed validation: {e}"
            )
            raise Unauthorized
        except SignatureExpired as e:
            self._logger.warning(
                f"Incoming cookie payload '{cookie}' no longer valid (too old/time mismatch): {e}"
            )
            raise Unauthorized
        except Exception as e:
            self._logger.error(f"Incoming cookie object: '{cookie}' problem: {e}")
            raise ServiceUnavailable

        self._logger.info(f"Finished verifying cookie: {cookie}")
        self._logger.info(f"Beginning to json decode: {cookie_value_json}")
        self._logger.debug(
            f"Incoming cookie object before decoding json: {cookie_value_json}"
        )
        try:
            cookie_payload = json.loads(cookie_value_json)
        except ValueError:
            self._logger.warning(
                f"Could not decode incoming verified cookie: {cookie_value_json}"
            )
            cookie_payload = None

        self._logger.info(f"Finished decoding cookie: {cookie_payload}")
        return cookie_payload

    def sign_cookie(self, cookie: dict, signing_key: str) -> str:
        """
        Sign and encode a cookie ready for transport and secure comms with trusted services
        :param cookie: dict of data to sign
        :param signing_key: key to sign data with
        :return: str signed cookie payload
        """
        self._logger.info(f"Starting to sign cookie: {cookie}")
        encoded_payload = json.dumps(cookie)

        try:
            result: str = (
                TimestampSigner(secret_key=signing_key)
                .sign(encoded_payload)
                .decode("utf8")
            )
        except Exception as e:
            self._logger.error(
                f"Unexpected problem signing cookie payload: {cookie}: {e}"
            )
            raise ServiceUnavailable

        self._logger.info(f"Finished signing cookie: {cookie}")
        return result

    def _extract_key_id(self, signed_cookie: str) -> [str, None]:
        """
        Extract the ``key_id`` from a signed and unverified cookie
        This is used to choose a key to verify this cookie, so it's not trusted at this stage
        :param signed_cookie: Signed cookie string
        :return: ``key_id``, used later on to choose a key
        """
        self._logger.info(f"Starting to extract key_id from {signed_cookie}")
        untrusted_payload_re = re.search(r"(.*\}+).*", signed_cookie)

        try:
            untrusted_payload = untrusted_payload_re.group(1)
        except AttributeError:
            self._logger.error(f"Untrusted cookie in wrong format: {signed_cookie}")
            raise Unauthorized

        try:
            untrusted_object = json.loads(untrusted_payload)
        except ValueError:
            self._logger.error(
                f"Unable to decode untrusted cookie to json: {signed_cookie}"
            )
            raise Unauthorized

        try:
            key_id = untrusted_object["key_id"]
        except KeyError:
            self._logger.warning(f"No key_id provided by cookie: {untrusted_payload}")
            key_id = None

        self._logger.info(f"Finished extracting key_id from {signed_cookie}")
        return key_id
