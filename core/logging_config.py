# core/logging_config.py
# DRAKBEN Structured Logging Configuration
# Provides consistent logging across all modules
import logging
import logging.handlers
import sys
from datetime import UTC, datetime
from pathlib import Path


class DrakbenFormatter(logging.Formatter):
    """Custom formatter for DRAKBEN logs.
    Provides colored output for terminal and structured format for files.
    """

    # ANSI color codes (Dracula theme compatible)
    COLORS = {
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",  # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[35m",  # Magenta
        "RESET": "\033[0m",
    }

    def __init__(self, use_colors: bool = True, include_module: bool = True) -> None:
        self.use_colors = use_colors and sys.stdout.isatty()
        self.include_module = include_module

        if include_module:
            fmt = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
        else:
            fmt = "%(asctime)s | %(levelname)-8s | %(message)s"

        super().__init__(fmt=fmt, datefmt="%Y-%m-%d %H:%M:%S")

    def format(self, record: logging.LogRecord) -> str:
        # Add colors for terminal output
        original_levelname = record.levelname
        if self.use_colors:
            color = self.COLORS.get(record.levelname, self.COLORS["RESET"])
            record.levelname = f"{color}{record.levelname}{self.COLORS['RESET']}"

        result = super().format(record)
        record.levelname = original_levelname
        return result


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging.
    Useful for log aggregation systems.
    """

    def format(self, record: logging.LogRecord) -> str:
        import json

        log_entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in (
                "name",
                "msg",
                "args",
                "created",
                "filename",
                "funcName",
                "levelname",
                "levelno",
                "lineno",
                "module",
                "msecs",
                "pathname",
                "process",
                "processName",
                "relativeCreated",
                "stack_info",
                "thread",
                "threadName",
                "exc_info",
                "exc_text",
                "message",
            ):
                log_entry[key] = value

        return json.dumps(log_entry, default=str)


def setup_logging(
    level: str = "INFO",
    log_dir: str = "logs",
    log_to_file: bool = True,
    log_to_console: bool = True,
    use_colors: bool = True,
    json_format: bool = False,
    max_file_size_mb: int = 10,
    backup_count: int = 5,
) -> logging.Logger:
    """Setup DRAKBEN logging configuration.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_dir: Directory for log files
        log_to_file: Enable file logging
        log_to_console: Enable console logging
        use_colors: Enable colored console output
        json_format: Use JSON format for file logs
        max_file_size_mb: Max size of each log file in MB
        backup_count: Number of backup log files to keep

    Returns:
        Root logger configured for DRAKBEN

    """
    # Get root logger for drakben
    root_logger = logging.getLogger("drakben")
    root_logger.setLevel(getattr(logging, level.upper()))

    # Close and clear existing handlers
    for handler in root_logger.handlers[:]:
        handler.close()
    root_logger.handlers.clear()

    # Console handler
    if log_to_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(getattr(logging, level.upper()))
        console_handler.setFormatter(DrakbenFormatter(use_colors=use_colors))
        root_logger.addHandler(console_handler)

    # File handler
    if log_to_file:
        log_path = Path(log_dir)
        log_path.mkdir(parents=True, exist_ok=True)

        # Main log file with rotation
        log_file = log_path / "drakben.log"
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_file_size_mb * 1024 * 1024,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(getattr(logging, level.upper()))

        if json_format:
            file_handler.setFormatter(JSONFormatter())
        else:
            file_handler.setFormatter(DrakbenFormatter(use_colors=False))

        root_logger.addHandler(file_handler)

        # Error log file (only errors and above)
        error_file = log_path / "drakben_error.log"
        error_handler = logging.handlers.RotatingFileHandler(
            error_file,
            maxBytes=max_file_size_mb * 1024 * 1024,
            backupCount=backup_count,
            encoding="utf-8",
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(DrakbenFormatter(use_colors=False))
        root_logger.addHandler(error_handler)

    # Suppress noisy third-party loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)

    return root_logger


def get_logger(name: str) -> logging.Logger:
    """Get a logger for a specific module.

    Args:
        name: Module name (e.g., 'core.brain', 'modules.recon')

    Returns:
        Logger instance

    Example:
        logger = get_logger(__name__)
        logger.info("Processing started")

    """
    # Prepend 'drakben' if not already present
    if not name.startswith("drakben"):
        name = f"drakben.{name}"

    return logging.getLogger(name)

