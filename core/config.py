import os
from dataclasses import dataclass
from typing import Optional

@dataclass
class SecurityConfig:
    log_channel_id: int
    alert_channel_id: Optional[int]
    quarantine_role_id: Optional[int]

    enable_sqlite: bool = False
    enable_safe_browsing: bool = False
    auto_ban_enabled: bool = False
    enable_clamav: bool = False
    enable_phish_db: bool = False
    enable_reactions: bool = True
    enable_rabbitmq: bool = False

    spam_threshold_per_10s: int = 5
    mention_threshold_per_msg: int = 3
    new_account_days: int = 7
    max_url_checks_per_day: int = 500

    monitor_voice_channels: bool = True
    monitor_role_changes: bool = True
    monitor_channel_changes: bool = True
    monitor_invite_creation: bool = True

    google_api_key: Optional[str] = None
    rabbitmq_url: str = os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost/")

def load_config() -> SecurityConfig:
    def _b(name: str, default: str = "0") -> bool:
        return (os.getenv(name, default).strip() in ("1", "true", "True"))

    return SecurityConfig(
        log_channel_id=int(os.getenv("LOG_CHANNEL_ID", "0")),
        alert_channel_id=int(os.getenv("ALERT_CHANNEL_ID", "0")) or None,
        quarantine_role_id=int(os.getenv("QUARANTINE_ROLE_ID", "0")) or None,
        enable_sqlite=_b("ENABLE_SQLITE", "0"),
        enable_safe_browsing=_b("ENABLE_SAFE_BROWSING", "0"),
        auto_ban_enabled=_b("AUTO_BAN_ENABLED", "0"),
        enable_clamav=_b("ENABLE_CLAMAV", "0"),
        enable_phish_db=_b("ENABLE_PHISH_DB", "0"),
        enable_rabbitmq=_b("ENABLE_RABBITMQ", "0"),
        google_api_key=os.getenv("GOOGLE_API_KEY") or None,
    )