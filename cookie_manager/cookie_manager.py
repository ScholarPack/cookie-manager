import json

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

    # TODO finish type decorating these
    def __init__(self, config: dict = None, logger=None) -> None:
        # TODO pull out and unit test this ratification/whitelist logic
        if config:
            for key, value in config.items():
                try:
                    # Only override existing values
                    self._config[key]
                except KeyError:
                    raise BadRequest
                self._config[key] = value

        if logger:
            self._logger = logger

    def decode_cookie(self, cookie: str, verify_key: str) -> [None, dict]:
        """
        Verify and decode a signed cookie payload from other internal services.
        Will trigger ``self.failure_func`` with a http status code upon error
        Logs status to ``self.logger``
        :param cookie: Signed payload for one cookie
        :param verify_key: Str used to verify original signer of cookie
        :return: Verified cookie dict payload, None,
        """
        self._logger.info(f"Starting to decode cookie: {cookie}")

        if cookie is None:
            self._logger.error(f"Incoming cookie '{cookie}' not provided.")
            raise Unauthorized
        try:
            cookie_value_json = TimestampSigner(verify_key).unsign(
                value=cookie, max_age=self._config.get("VERIFY_MAX_COOKIE_AGE", 50)
            )
        except BadSignature as e:
            self._logger.error(
                f"Incoming cookie payload: '{cookie}' failed validation: {e}"
            )
            raise Unauthorized
        except SignatureExpired as e:
            self._logger.error(
                f"Incoming cookie payload '{cookie}' no longer valid (too old/time mismatch): {e}"
            )
            raise Unauthorized
        except Exception as e:
            self._logger.error(f"Incoming cookie object: '{cookie}' problem: {e}")
            raise ServiceUnavailable

        self._logger.debug(
            f"Incoming cookie object before decoding: {cookie_value_json}"
        )
        try:
            cookie_payload = json.loads(cookie_value_json)
        except ValueError:
            self._logger.warning(
                f"Could not decode incoming cookie: {cookie_value_json}"
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

        return result
