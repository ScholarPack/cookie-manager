import json

from flask import abort, current_app as app
from itsdangerous import TimestampSigner, BadSignature, SignatureExpired


class CookieManager:
    MAX_AGE: int = None

    def __init__(self):
        self.MAX_AGE = app.config.get("COOKIE_UNSIGN_MAX_AGE", 30)

    def decode_cookie(self, cookie: str, unsigning_key: str) -> [None, dict]:
        """
        Verify and decode a signed cookie payload from other internal services.
        Will abort if unauthorised
        :param cookie: Signed payload for one cookie
        :param unsigning_key: Str used to verify original signer of cookie
        :return: Verified cookie dict payload, None,
        """
        cookie_value_json = None

        if cookie is None:
            app.logger.error(f"Incoming cookie '{cookie}' not provided.")
            abort(401)
        try:
            cookie_value_json = TimestampSigner(unsigning_key).unsign(
                cookie, max_age=self.MAX_AGE
            )
        except BadSignature as e:
            app.logger.error(
                f"Incoming cookie payload: '{cookie}' failed validation: {e}"
            )
            abort(401)
        except SignatureExpired as e:
            app.logger.error(
                f"Incoming cookie payload '{cookie}' no longer valid (too old/time mismatch): {e}"
            )
            abort(401)
        except Exception as e:
            app.logger.error(f"Incoming cookie object: '{cookie}' problem: {e}")
            abort(503)

        app.logger.debug(f"Incoming cookie object before decoding: {cookie_value_json}")
        try:
            cookie_payload = json.loads(cookie_value_json)
        except ValueError:
            app.logger.warning(f"Could not decode incoming cookie: {cookie_value_json}")
            cookie_payload = None

        return cookie_payload

    @staticmethod
    def sign_cookie(cookie: dict, signing_key: str) -> str:
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
            app.logger.error(
                f"Unexpected problem signing cookie payload: {cookie}: {e}"
            )
            raise

        return result
