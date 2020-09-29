![Validate Build](https://github.com/ScholarPack/cookie-manager/workflows/Validate%20Build/badge.svg?branch=master)

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

## Configuration

You can pass an optional config dictionary into the constructor to override existing options.

```python
cookie_manager = CookieManager(keys=keys, config={"VERIFY_MAX_COOKIE_AGE": 10})
```

This example will override the max age of a cookie that is allowed, when verifying.

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

# Security Decorators
If using this package in *flask*, you can decorate routes to only allow access to certain cookies.

There are 2 ways of protecting a route, allow any signed cookie or allow cookies signed with specific keys.

To make use of the decorators, you will need to create a cookie manager that has all the keys you want to use for
protecting routes and create an instance of the `CookieSecurityDecorator`.

*Decorator instance (e.g. util.py)*
```python
from cookie_manager import CookieSecurityDecorator
cookie_security = CookieSecurityDecorator()
```

```python
from cookie_manager import CookieManager
from project.util import cookie_security
from flask import request
cookie_manager = CookieManager(
    keys={"key_1": "", "key_2": "", "key_3": ""}, # These are the keys that will be used to protect all routes
    exceptions=exceptions,
)
cookie_security.init_app(request=request, cookie_manager=cookie_manager, cookie_name="cookie_name")
```

The string supplied for `cookie_name` is the name of the cookie in the request to use for protecting the routes.

Now you are able to use the decorator as detailed below.

**Option 1** - Allow access to any signed cookie

Lets say we want to have a route that can be accessed by any cookie that has been signed using one of the keys
supplied to the cookie manager used to create the decorator. If we decorate the route like the following example,
only signed cookies will be allowed to access this route.

```python
from project.util import cookie_security
@cookie_security.keys_required()
def my_route():
    #...
```

**Option 2** - Allow access to specific signed cookies

Lets say we want to have a route that can only be accessed by a cookie that has been signed using a subset of keys supplied to
the cookie manager used to create the decorator. If we decorate the route like the following example, only cookies signed with
a provided key will be allowed to access this route.

```python
from project.util import cookie_security
@cookie_security.keys_required(["key_1", "key_2"])
def my_route():
    #...
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
