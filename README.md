# Cookie-Manager
Signed cookie manager for communication between multiple trusted services.

Signs, verifies, and manages multiple cookies from trusted environments. Designed for use by services all within the same secure network (AWS VPC etc).

Wraps [itsdangerous](https://github.com/pallets/itsdangerous) for the signing and verification (but this could change in the future). 

Specifically, this handles:
- Managing multiple different cookies - one for every environment or paired service
- Error correction around sign/verify commands

This package is designed to sign and verify cookies - either ingoing or outgoing. These cookies are not encrypted, 
so stick to benign data, and only transmit within a trusted environment such as an AWS VPC.

# Installation
Install and update using `pip`:

```bash 
pip install -U Cookie-Manager
```

# Usage

Import:

```python
from cookie_manager.cookie_manager import CookieManager
```

Cookie-Manager is designed to use multiple different signing/verifying keys -- one (or more) per environment.
Configure your keys in a dict:

```python
keys = {"key1": "SECRET", "key2": "SECRET2"}
```

Create an instance (and seed it with your keys):

```python
cookie_manager = CookieManager(keys=keys)
```

## Signing

To sign a cookie, start with a dict payload containing your data:

```python
payload = {"key": "value"}
```

Then sign the payload, making sure to pass a valid `key_id` as previously configured. The `sign` method will
retrieve your signing key `SECRET` to sign requests (based on the `key_id` you pass in). This WILL override any
existing key with the name `key_id`.

```python
signed_cookie = cookie_manager.sign(cookie=payload, key_id="key1")
```

This will return you a signed cookie (with an additional `key_id` pair added in):

```python
'{"key": "value", "key_id": "key1"}.XepkCA.CUZtVTCXHbqoalWVCh5xOa4S4WE'
```

## Verifying

When reading in a signed cookie, verification happens through the cookie payload -> whatever comes in needs to have a 
`key_id` in the payload, which is used to lookup the verification key (configured during instantiation). This is added
for you by `sign`:

```python
incoming_signed_cookie = '{"key": "value", "key_id", "key1"}.XepkCA.CUZtVTCXHbqoalWVCh5xOa4S4WE'
```

Verify this cookie (during which Cookie-Manager will extract `key_id` from the payload, and lookup the key used to sign the cookie):

```python
payload = cookie_manager.verify(signed_cookie=signed_cookie)
```

Now, you can access data inside the `payload` object. The `verify` function will raise errors if it cannot verify.

# Custom Logging
This package uses dependency injection to log errors with Python's `print`. To use your own logger, pass in a
logger object which implements `critical`, `error`, `warning`, `debug`, and `info` functions. Here's how to patch
in the Flask logger, but any object will work providing it meets the Duck Typing rules:

```python
cookie_manager = CookieManager(keys=keys, logger=app.logger)
```

This will result in logging calls firing to `app.logger.<logger-level>` with a string passed in.

# Custom Exceptions
Like logging, this package uses custom error handling if you need it. By default, all errors will raise as
"Exception", but you can pass in a custom object to raise specific errors.

This class will raise `Unauthorized`, `ServiceUnavailable`, and `BadRequest`.

Here's how to pass in a [Werkzeug](https://github.com/pallets/werkzeug) exception object:

```python
from werkzeug import exceptions
cookie_manager = CookieManager(keys=keys, exceptions=exceptions)
```

# Developing
__The build pipeline require your tests to pass and code to be formatted__

Make sure you have Python 3.x installed on your machine (use [pyenv](https://github.com/pyenv/pyenv)).

Install the dependencies with [pipenv](https://github.com/pypa/pipenv) (making sure to include dev and pre-release packages):

```bash
pipenv install --dev --pre
```

Configure your environment:

```bash
pipenv shell && export PYTHONPATH="$PWD"
```

Run the tests:

```bash
pytest
```

Or with logging:

```bash
pytest -s
```

Or tests with coverage:

```bash
pytest --cov=./
```

Format the code with [Black](https://github.com/psf/black):

```bash
black $PWD
```

# Releases
Cleanup the (.gitignored) `dist` folder (if you have one):

```bash
rm -rf dist
```

Notch up the version number in `setup.py` and build:

```bash
python3 setup.py sdist bdist_wheel
```

Push to PyPi (using the ScholarPack credentials when prompted)

```bash
python3 -m twine upload --repository-url https://upload.pypi.org/legacy/ dist/*
```

# Links
* Releases: https://pypi.org/project/cookie-manager/
* Code: https://github.com/ScholarPack/cookie-manager/
