import logging

from flask import Flask
from flask_wtf import CSRFProtect

from .config import BaseConfig, get_config_class
from .main import main_bp
from .auth import auth_bp


csrf = CSRFProtect()


def _configure_logging(app: Flask) -> None:
    """Configure application logging from the LOG_LEVEL config value."""

    log_level_name = app.config.get("LOG_LEVEL", "INFO")
    log_level = getattr(logging, str(log_level_name).upper(), logging.INFO)
    logging.basicConfig(level=log_level)
    app.logger.setLevel(log_level)


def _register_error_handlers(app: Flask) -> None:
    """Register simple centralized error handlers."""

    @app.errorhandler(400)
    def handle_bad_request(error):  # type: ignore[unused-argument]
        app.logger.warning("Bad request: %s", error)
        return "Bad request", 400

    @app.errorhandler(500)
    def handle_internal_error(error):  # type: ignore[unused-argument]
        app.logger.error("Internal server error: %s", error)
        return "Internal server error", 500


def create_app(config_class: type[BaseConfig] | None = None) -> Flask:
    """Application factory for the Entra SSO Flask app."""

    if config_class is None:
        config_class = get_config_class()

    app = Flask(__name__)
    app.config.from_object(config_class)

    # Enable CSRF protection for state-changing requests.
    csrf.init_app(app)

    _configure_logging(app)
    config_class.validate(app.config)

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    _register_error_handlers(app)

    return app

