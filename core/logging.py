import logging, os
from logging.handlers import RotatingFileHandler

LOGGER = logging.getLogger("security-bot")

def apply_logging() -> logging.Logger:
    LOGGER.setLevel(logging.INFO)
    os.makedirs("logs", exist_ok=True)

    file_handler = RotatingFileHandler(
        filename=os.path.join("logs", "bot.log"),
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s:%(lineno)d | %(message)s")
    file_handler.setFormatter(fmt)

    console = logging.StreamHandler()
    console.setFormatter(fmt)

    if not any(isinstance(h, RotatingFileHandler) for h in LOGGER.handlers):
        LOGGER.addHandler(file_handler)
    if not any(isinstance(h, logging.StreamHandler) for h in LOGGER.handlers):
        LOGGER.addHandler(console)
    return LOGGER