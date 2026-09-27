import logging

logger = logging.getLogger(__name__)

SUPPORT_EMAIL = "help@example.invalid"
RELEASED_AT = "2024-01-01 12:00:00"
TIMEOUT_MS = 1000000000
OWNER = {"name": "Maria Rossi", "email": "maria.rossi@gmail.com"}


def create_user(user, email_enabled):
    logger.info("email_enabled=%s", email_enabled)
    logger.info(f"created {user}")
    logger.info("created user_id=%s", user.id)
    print("server address", "0.0.0.0")
    return user
