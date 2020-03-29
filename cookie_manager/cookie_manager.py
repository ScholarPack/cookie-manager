import json
import re

from itsdangerous import TimestampSigner, BadSignature, SignatureExpired


class CookieManager:
    _config: dict = {
        "VERIFY_MAX_COOKIE_AGE": 50,  # Cookie TTL in seconds (enforced when verifying, not when signing)
    }
    _logger = type(
        "logger",
        (),
        {
            "critical": lambda msg: print(msg),
            "error": lambda msg: print(msg),
            "warning": lambda msg: print(msg),
            "debug": lambda msg: print(msg),
            "info": lambda msg: print(msg),
        },
    )
    _exceptions = type(
        "exception",
        (),
        {
            "Unauthorized": Exception,
            "ServiceUnavailable": Exception,
            "BadRequest": Exception,
        },
    )
    _keys = {}  # Signing/verification keys in the format {"key_id": "key")

    def __init__(
        self, keys: dict, config: dict = None, logger=None, exceptions=None
    ) -> None:
        if config:
            self._config = self._override_config(override_config=config)
        if logger:
            self._logger = logger

        if keys is None:
            self._logger.critical(f"Signing/verification keys not supplied.")
            raise self._exceptions.ServiceUnavailable

        if exceptions:
            self._exceptions = exceptions

        self._keys = keys
        self._logger.info(f"Finished configuring cookie manager")

    def sign(self, cookie: dict, key_id: str) -> str:
        """
        Sign and encode a cookie ready for transport and secure comms with trusted services
        Use a pre-registered signing key, looked up through ``key`` and ``self._keys``
        Will add ``key_id`` to the cookie payload (used to verify)
        :param cookie: Cookie dict to sign, e.g. {"A": "A"}
        :param key_id: Id of signing key registered in ``self._keys``
        :return: Signed cookie string, e.g. {"A": "A"}.ABCD.12345678
        """
        self._logger.info(f"Starting to sign cookie: {cookie} with key_id: {key_id}")
        try:
            signing_key = self._keys[key_id]
        except KeyError:
            self._logger.error(f"Bad lookup for signing key_id: {key_id}")
            raise self._exceptions.ServiceUnavailable

        cookie["key_id"] = key_id
        signed_cookie = self._sign_cookie(cookie=cookie, signing_key=signing_key)
        return signed_cookie

    def verify(self, signed_cookie: str) -> dict:
        """
        Takes a signed cookie, extracts the ``key_id`` embedded in it, and verifies then decodes the cookie
        :param signed_cookie: Signed cookie payload, containing a ``key_id`` that matches a key in ``self._keys``
        :return: Unsigned, trusted cookie as an object
        """
        key_id = self._extract_key_id(signed_cookie=signed_cookie)
        try:
            key = self._keys[key_id]
        except KeyError:
            self._logger.error(f"Bad lookup for verifying key_id: {key_id}")
            raise self._exceptions.ServiceUnavailable

        return self._decode_verify_cookie(cookie=signed_cookie, verify_key=key)

    def _override_config(self, override_config: dict) -> dict:
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
                    raise self._exceptions.BadRequest
                new_config[key] = value

        self._logger.info(f"Finished comparing config: {override_config}")
        return new_config

    def _decode_verify_cookie(self, cookie: str, verify_key: str) -> [None, dict]:
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
            raise self._exceptions.Unauthorized
        try:
            self._logger.debug(f"Beginning verification: {cookie}")
            cookie_value = TimestampSigner(verify_key).unsign(
                value=cookie, max_age=self._config.get("VERIFY_MAX_COOKIE_AGE", 50)
            )
        except BadSignature as e:
            self._logger.warning(
                f"Incoming cookie payload: '{cookie}' failed validation: {e}"
            )
            raise self._exceptions.Unauthorized
        except SignatureExpired as e:
            self._logger.warning(
                f"Incoming cookie payload '{cookie}' no longer valid (too old/time mismatch): {e}"
            )
            raise self._exceptions.Unauthorized
        except Exception as e:
            self._logger.error(f"Incoming cookie object: '{cookie}' problem: {e}")
            raise self._exceptions.ServiceUnavailable

        self._logger.info(f"Finished verifying cookie: {cookie}")
        self._logger.info(f"Beginning to json decode: {cookie_value}")
        try:
            cookie_payload = json.loads(cookie_value)
        except ValueError:
            self._logger.warning(
                f"Could not decode incoming verified cookie: {cookie_value}"
            )
            cookie_payload = None

        self._logger.info(f"Finished decoding cookie: {cookie_payload}")
        return cookie_payload

    def _sign_cookie(self, cookie: dict, signing_key: str) -> str:
        """
        Sign and encode a cookie ready for transport and secure comms with trusted services
        Use ``self.sign_cookie`` for public use
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
            raise self._exceptions.ServiceUnavailable

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
            raise self._exceptions.Unauthorized

        try:
            untrusted_object = json.loads(untrusted_payload)
        except ValueError:
            self._logger.error(
                f"Unable to decode untrusted cookie to json: {signed_cookie}"
            )
            raise self._exceptions.Unauthorized

        try:
            key_id = untrusted_object["key_id"]
        except KeyError:
            self._logger.warning(f"No key_id provided by cookie: {untrusted_payload}")
            key_id = None

        self._logger.info(f"Finished extracting key_id from {signed_cookie}")
        return key_id
