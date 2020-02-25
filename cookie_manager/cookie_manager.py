import json

from itsdangerous import TimestampSigner, BadSignature, SignatureExpired
from werkzeug.exceptions import abort


class CookieManager:
    config: dict = {
        "VERIFY_MAX_COOKIE_AGE": 50,  # Cookie TTL in seconds (enforced when verifying, not when signing)
    }
    logger = type(
        "logger",
        (),
        {
            "error": lambda msg: None,
            "warning": lambda msg: None,
            "debug": lambda msg: None,
        },
    )
    failure_func = (
        abort  # Function to call when there is an error. Called with a HTTP status code
    )

    # TODO finish type decorating these
    def __init__(self, config: dict = None, logger=None, failure_func=None) -> None:
        # TODO pull out and unit test this ratification/whitelist logic
        if config:
            for key, value in config.items():
                try:
                    # Only override existing values
                    self.config[key]
                except KeyError:
                    self.failure_func(400)
                self.config[key] = value

        if logger:
            self.logger = logger

        if failure_func:
            self.failure_func = failure_func

    def decode_cookie(self, cookie: str, verify_key: str) -> [None, dict]:
        """
        Verify and decode a signed cookie payload from other internal services.
        Will abort if unauthorised
        :param cookie: Signed payload for one cookie
        :param verify_key: Str used to verify original signer of cookie
        :return: Verified cookie dict payload, None,
        """
        cookie_value_json = None

        if cookie is None:
            self.logger.error(f"Incoming cookie '{cookie}' not provided.")
            self.failure_func(401)
        try:
            cookie_value_json = TimestampSigner(verify_key).unsign(
                cookie, max_age=self.config.get("VERIFY_MAX_COOKIE_AGE", 50)
            )
        except BadSignature as e:
            self.logger.error(
                f"Incoming cookie payload: '{cookie}' failed validation: {e}"
            )
            self.failure_func(401)
        except SignatureExpired as e:
            self.logger.error(
                f"Incoming cookie payload '{cookie}' no longer valid (too old/time mismatch): {e}"
            )
            self.failure_func(401)
        except Exception as e:
            self.logger.error(f"Incoming cookie object: '{cookie}' problem: {e}")
            self.failure_func(503)

        self.logger.debug(
            f"Incoming cookie object before decoding: {cookie_value_json}"
        )
        try:
            cookie_payload = json.loads(cookie_value_json)
        except ValueError:
            self.logger.warning(
                f"Could not decode incoming cookie: {cookie_value_json}"
            )
            cookie_payload = None

        return cookie_payload

    def sign_cookie(self, cookie: dict, signing_key: str) -> str:
        """
        Sign and encode a cookie ready for transport and secure comms with services
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
            self.logger.error(
                f"Unexpected problem signing cookie payload: {cookie}: {e}"
            )
            raise

        return result
