import pytest

from parent_management.app import create_app


@pytest.fixture(scope="session", autouse=True)
def test_app():
    """
    Build a basic testing app with an application context
    """
    app = create_app(config_file="test_config.py")
    app.app_context().push()

    yield app
