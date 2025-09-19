from __future__ import annotations
import asyncio
import logging
from logging.handlers import RotatingFileHandler
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from collections import defaultdict, deque
from datetime import datetime
from zoneinfo import ZoneInfo
import os
import re
import hashlib
import urllib.parse

import discord
from discord.ext import commands

// 선택 의존성 로드
try:
    import aiohttp
except Exception:
    aiohttp = None
try:
    import aiosqlite
except Exception:
    aiosqlite = None

TZ = ZoneInfo("Asia/Seoul")

// 보안 설정 클래스
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

    spam_threshold_per_10s: int = 5
    mention_threshold_per_msg: int = 3
    new_account_days: int = 7
    max_url_checks_per_day: int = 500

    monitor_voice_channels: bool = True
    monitor_role_changes: bool = True
    monitor_channel_changes: bool = True
    monitor_invite_creation: bool = True

    google_api_key: Optional[str] = None

// 환경변수에서 설정 로드
def load_config() -> SecurityConfig:
    def _b(name: str, default: str = "0") -> bool:
        return os.getenv(name, default).strip().lower() in ("1", "true")
    return SecurityConfig(
        log_channel_id=int(os.getenv("LOG_CHANNEL_ID", "0")),
        alert_channel_id=int(os.getenv("ALERT_CHANNEL_ID", "0")) or None,
        quarantine_role_id=int(os.getenv("QUARANTINE_ROLE_ID", "0")) or None,
        enable_sqlite=_b("ENABLE_SQLITE", "1"),
        enable_safe_browsing=_b("ENABLE_SAFE_BROWSING", "0"),
        auto_ban_enabled=_b("AUTO_BAN_ENABLED", "0"),
        enable_clamav=_b("ENABLE_CLAMAV", "0"),
        enable_phish_db=_b("ENABLE_PHISH_DB", "0"),
        google_api_key=os.getenv("GOOGLE_API_KEY") or None,
    )

// 로거 설정
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

// URL 패턴
URL_REGEX = re.compile(r"https?://[^\s<>()]+")

// 위험한 확장자 목록
DANGEROUS_EXTS = [
    ".exe", ".scr", ".pif", ".com", ".bat", ".cmd", ".msi",
    ".dll", ".jar", ".vbs", ".js", ".ps1",
    ".zip", ".rar", ".7z", ".tar.gz"
]

// 글로벌 화이트리스트 도메인
SAFE_DOMAINS: tuple[str, ...] = (
    "youtube.com", "youtu.be", "google.com", "github.com",
    "wikipedia.org", "reddit.com", "discord.com", "discordapp.com",
)

// 의심 도메인 패턴
SUSPICIOUS_DOMAIN_PATTERNS: tuple[re.Pattern, ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (r".*discord.*nitro.*", r".*steam.*gift.*", r"bit\.ly", r"tinyurl\.com", r"t\.co")
)

// 위험 점수 가중치
RISK_WEIGHTS = {
    "new_account_1d": 20,
    "new_account_ndays": 10,
    "fast_msgs_high": 15,
    "fast_msgs_mid": 10,
    "dup_msg": 12,
    "server_attack": 30,
    "phishing": 40,
    "channel_hopping": 10,
    "mention_over": 8,
    "danger_ext": 30,
    "danger_ext_exec_bonus": 20,
    "spam_window": 15,
    "mention_spam": 12,
    "url_high": 35,
    "url_med": 20,
    "url_low": 10,
}

// 사용자 활동 기록
user_activity: Dict[int, Dict] = defaultdict(lambda: {
    "message_times": deque(maxlen=20),
    "message_hashes": deque(maxlen=10),
    "reaction_times": deque(maxlen=15),
    "warnings": 0,
    "risk_score": 0,
    "last_channel_ids": deque(maxlen=5),
    "voice_hops": deque(maxlen=10),
})

// 서버 활동 기록
server_activity: Dict[int, Dict] = defaultdict(lambda: {
    "channel_creations": deque(maxlen=20),
    "role_creations": deque(maxlen=20),
    "mass_bans": deque(maxlen=10),
    "webhook_creations": deque(maxlen=15),
    "invite_creations": deque(maxlen=30),
})

// DB 파일 경로
DB_PATH = "security.db"
_http: Optional["aiohttp.ClientSession"] = None

// DB 초기화용 SQL
CREATE_SQL = """
CREATE TABLE IF NOT EXISTS blacklist_users(user_id INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS blacklist_domains(domain TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS url_stats(day TEXT PRIMARY KEY, total_checked INTEGER NOT NULL DEFAULT 0, malicious_found INTEGER NOT NULL DEFAULT 0);

CREATE TABLE IF NOT EXISTS guild_settings(
    guild_id INTEGER PRIMARY KEY,
    log_channel_id INTEGER,
    alert_channel_id INTEGER,
    quarantine_role_id INTEGER
);

CREATE TABLE IF NOT EXISTS whitelist_domains(
    guild_id INTEGER NOT NULL,
    domain TEXT NOT NULL,
    PRIMARY KEY(guild_id, domain)
);
"""

// 로그 전송 함수
async def send_log(bot: commands.Bot, cfg: SecurityConfig, message: str, *, guild_id: Optional[int] = None, alert: bool = False):
    LOGGER.info(("ALERT: " if alert else "LOG: ") + message)
    ch = None
    if guild_id is not None:
        gs = await get_guild_settings_cached(guild_id)
        if gs and gs.get("log_channel_id"):
            ch = bot.get_channel(gs["log_channel_id"])
    if ch is None:
        channel_id = cfg.alert_channel_id if (alert and cfg.alert_channel_id) else cfg.log_channel_id
        if not channel_id:
            return
        ch = bot.get_channel(channel_id)
    if not ch:
        return
    try:
        if alert:
            embed = discord.Embed(title="🚨 보안 경고", description=message, color=0xFF0000, timestamp=datetime.now(TZ))
            embed.set_footer(text="Security Bot")
            await ch.send(embed=embed)
        else:
            await ch.send(f"`{message}`")
    except Exception:
        LOGGER.exception("send_log 오류")

async def db_init(cfg: SecurityConfig):
    if not (cfg.enable_sqlite and aiosqlite):
        LOGGER.info("SQLite 비활성: guild settings는 메모리에서 유지됩니다")
        return
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(CREATE_SQL)
        await db.commit()
    LOGGER.info("SQLite 초기화 완료")

# guild 설정 저장
async def set_guild_settings(guild_id: int, settings: Dict[str, Optional[int]], cfg: SecurityConfig):
    if cfg.enable_sqlite and aiosqlite:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "INSERT INTO guild_settings(guild_id, log_channel_id, alert_channel_id, quarantine_role_id) VALUES(?,?,?,?) "
                "ON CONFLICT(guild_id) DO UPDATE SET log_channel_id=excluded.log_channel_id, alert_channel_id=excluded.alert_channel_id, quarantine_role_id=excluded.quarantine_role_id",
                (guild_id, settings.get("log_channel_id"), settings.get("alert_channel_id"), settings.get("quarantine_role_id"))
            )
            await db.commit()
    else:
        _in_memory_guild_settings[guild_id] = settings.copy()

# guild 설정 조회
async def get_guild_settings(guild_id: int, cfg: SecurityConfig) -> Dict[str, Optional[int]]:
    if cfg.enable_sqlite and aiosqlite:
        async with aiosqlite.connect(DB_PATH) as db:
            async with db.execute("SELECT log_channel_id, alert_channel_id, quarantine_role_id FROM guild_settings WHERE guild_id=?", (guild_id,)) as cur:
                row = await cur.fetchone()
                if row:
                    return {"log_channel_id": row[0], "alert_channel_id": row[1], "quarantine_role_id": row[2]}
                return {"log_channel_id": None, "alert_channel_id": None, "quarantine_role_id": None}
    else:
        return _in_memory_guild_settings.get(guild_id, {"log_channel_id": None, "alert_channel_id": None, "quarantine_role_id": None})

# guild 설정 캐시 조회
_guild_settings_cache: Dict[int, Dict] = {}
async def get_guild_settings_cached(guild_id: int) -> Dict[str, Optional[int]]:
    if guild_id in _guild_settings_cache:
        return _guild_settings_cache[guild_id]
    cfg = load_config()
    gs = await get_guild_settings(guild_id, cfg)
    _guild_settings_cache[guild_id] = gs
    return gs

# 화이트리스트 도메인 추가
async def add_whitelist_domain(guild_id: int, domain: str, cfg: SecurityConfig):
    domain = domain.lower()
    if cfg.enable_sqlite and aiosqlite:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("INSERT OR IGNORE INTO whitelist_domains(guild_id, domain) VALUES(?,?)", (guild_id, domain))
            await db.commit()
    else:
        _in_memory_whitelists[guild_id].add(domain)
    if guild_id in _guild_settings_cache:
        _guild_settings_cache.pop(guild_id, None)

# 화이트리스트 도메인 제거
async def remove_whitelist_domain(guild_id: int, domain: str, cfg: SecurityConfig):
    domain = domain.lower()
    if cfg.enable_sqlite and aiosqlite:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("DELETE FROM whitelist_domains WHERE guild_id=? AND domain=?", (guild_id, domain))
            await db.commit()
    else:
        _in_memory_whitelists[guild_id].discard(domain)
    if guild_id in _guild_settings_cache:
        _guild_settings_cache.pop(guild_id, None)

# 화이트리스트 도메인 목록 조회
async def list_whitelist_domains(guild_id: int, cfg: SecurityConfig) -> List[str]:
    if cfg.enable_sqlite and aiosqlite:
        async with aiosqlite.connect(DB_PATH) as db:
            async with db.execute("SELECT domain FROM whitelist_domains WHERE guild_id=?", (guild_id,)) as cur:
                rows = await cur.fetchall()
                return [r[0] for r in rows]
    else:
        return list(_in_memory_whitelists.get(guild_id, set()))

# 도메인이 화이트리스트에 있는지 확인
async def is_domain_whitelisted(guild_id: int, domain: str, cfg: SecurityConfig) -> bool:
    domain = domain.lower()
    if cfg.enable_sqlite and aiosqlite:
        async with aiosqlite.connect(DB_PATH) as db:
            async with db.execute("SELECT 1 FROM whitelist_domains WHERE guild_id=? AND domain=?", (guild_id, domain)) as cur:
                return (await cur.fetchone()) is not None
    else:
        return domain in _in_memory_whitelists.get(guild_id, set())

# 블랙리스트 사용자 추가
async def db_add_black_user(uid: int, cfg: SecurityConfig):
    if not (cfg.enable_sqlite and aiosqlite):
        return
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("INSERT OR IGNORE INTO blacklist_users(user_id) VALUES(?)", (uid,))
        await db.commit()

# 블랙리스트 사용자 확인
async def db_is_black_user(uid: int, cfg: SecurityConfig) -> bool:
    if not (cfg.enable_sqlite and aiosqlite):
        return False
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT 1 FROM blacklist_users WHERE user_id=?", (uid,)) as cur:
            return (await cur.fetchone()) is not None

# 블랙리스트 도메인 추가
async def db_add_black_domain(domain: str, cfg: SecurityConfig):
    if not (cfg.enable_sqlite and aiosqlite):
        return
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("INSERT OR IGNORE INTO blacklist_domains(domain) VALUES(?)", (domain,))
        await db.commit()

# 블랙리스트 도메인 확인
async def db_is_black_domain(domain: str, cfg: SecurityConfig) -> bool:
    if not (cfg.enable_sqlite and aiosqlite):
        return False
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT 1 FROM blacklist_domains WHERE domain=?", (domain,)) as cur:
            return (await cur.fetchone()) is not None

# URL 통계 업데이트
async def db_url_inc(total=0, bad=0, cfg: SecurityConfig | None = None):
    if not (cfg and cfg.enable_sqlite and aiosqlite):
        return
    day = datetime.now(TZ).date().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO url_stats(day,total_checked,malicious_found) VALUES(?,?,?) "
            "ON CONFLICT(day) DO UPDATE SET total_checked=total_checked+?, malicious_found=malicious_found+?",
            (day, total, bad, total, bad)
        )
        await db.commit()

# 위험 점수 계산
def _calc_risk(user_id: int, msg: discord.Message, cfg: SecurityConfig) -> int:
    score = 0
    u = user_activity[user_id]
    now_utc = discord.utils.utcnow()
    now_ts = now_utc.timestamp()
    created = getattr(msg.author, "created_at", None)
    if created:
        days = (now_utc - created).days
        if days < 1:
            score += RISK_WEIGHTS["new_account_1d"]
        elif days < cfg.new_account_days:
            score += RISK_WEIGHTS["new_account_ndays"]
    recent60 = [t for t in u["message_times"] if now_ts - t < 60]
    if len(recent60) > 15:
        score += RISK_WEIGHTS["fast_msgs_high"]
    elif len(recent60) > 10:
        score += RISK_WEIGHTS["fast_msgs_mid"]
    h = hashlib.md5(msg.content.encode("utf-8", "ignore")).hexdigest()
    if h in u["message_hashes"]:
        score += RISK_WEIGHTS["dup_msg"]
    mcount = len(msg.mentions) + len(msg.role_mentions)
    if mcount > cfg.mention_threshold_per_msg:
        score += (mcount - cfg.mention_threshold_per_msg) * RISK_WEIGHTS["mention_over"]
    u["last_channel_ids"].append(msg.channel.id)
    if len(set(u["last_channel_ids"])) >= 4:
        score += RISK_WEIGHTS["channel_hopping"]
    return min(score, 100)

# URL 검사 함수
async def _pattern_url_bad(url: str, cfg: SecurityConfig, guild_id: Optional[int] = None) -> Tuple[bool, str]:
    try:
        p = urllib.parse.urlparse(url)
        domain = p.netloc.lower()
        if guild_id is not None:
            if await is_domain_whitelisted(guild_id, domain, cfg):
                return False, "Guild 화이트리스트"
        if domain.endswith(SAFE_DOMAINS):
            return False, "화이트리스트"
        if cfg.enable_sqlite and await db_is_black_domain(domain, cfg):
            return True, "블랙리스트 도메인"
        for pat in SUSPICIOUS_DOMAIN_PATTERNS:
            if pat.search(domain):
                return True, f"의심 도메인: {pat.pattern}"
        if len(p.path) > 150 or p.path.count('/') > 8:
            return True, "비정상 URL 구조"
        return False, "패턴 통과"
    except Exception as e:
        return True, f"URL 파싱 오류: {e}"

# GSB 검사 함수
async def _gsb_check(url: str, cfg: SecurityConfig) -> Tuple[bool, str]:
    if not (cfg.enable_safe_browsing and cfg.google_api_key and aiohttp):
        return await _pattern_url_bad(url, cfg)
    await db_url_inc(total=1, cfg=cfg)
    api = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {"clientId": "security-bot", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    for attempt in range(3):
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with _http.post(api, json=payload, params={"key": cfg.google_api_key}, timeout=timeout) as r:
                if r.status == 200:
                    data = await r.json()
                    if data.get("matches"):
                        await db_url_inc(bad=1, cfg=cfg)
                        return True, "GSB 위협 감지"
                    return False, "GSB 안전"
                if r.status in (429, 503):
                    await asyncio.sleep(2 ** attempt)
                    continue
                return await _pattern_url_bad(url, cfg)
        except Exception:
            return await _pattern_url_bad(url, cfg)
    return await _pattern_url_bad(url, cfg)

# URL 추출 및 검사
async def extract_and_check_urls(text: str, cfg: SecurityConfig, guild_id: Optional[int] = None) -> List[dict]:
    urls = URL_REGEX.findall(text)
    out: List[dict] = []
    for u in urls:
        if not u.startswith(("http://", "https://")):
            u = "https://" + u
        bad, reason = await _pattern_url_bad(u, cfg, guild_id=guild_id)
        if not bad:
            bad2, reason2 = await _gsb_check(u, cfg)
            bad = bad or bad2
            reason = reason if not bad2 else reason2
        if bad:
            sev = "high" if any(k in reason.lower() for k in ("malware", "social", "phishing")) else "medium"
            out.append({"url": u, "reason": reason, "severity": sev})
            if cfg.enable_sqlite and not urllib.parse.urlparse(u).netloc.lower().endswith(SAFE_DOMAINS):
                await db_add_black_domain(urllib.parse.urlparse(u).netloc.lower(), cfg)
    return out

# 자동 조치 함수
async def _moderate(bot: commands.Bot, cfg: SecurityConfig, message: discord.Message, risk: int, threats: List[str], mal_urls: Optional[List[dict]]):
    user = message.author
    guild = message.guild
    try:
        await message.delete()
    except Exception:
        pass
    if not cfg.auto_ban_enabled:
        await send_log(bot, cfg, f"🔸 경고(시뮬레이트): {user} | 위험도 {risk} | 위협 {', '.join(threats) if threats else '-'}", guild_id=(guild.id if guild else None))
        return
    if risk >= 80:
        try:
            await user.ban(reason=f"자동 차단 - 위험도 {risk}")
            if cfg.enable_sqlite:
                await db_add_black_user(user.id, cfg)
            await send_log(bot, cfg, f"🔥 자동 차단: {user} | 위험 {risk}", guild_id=(guild.id if guild else None), alert=True)
        except discord.Forbidden:
            await send_log(bot, cfg, f"❌ 차단 권한 부족: {user}", guild_id=(guild.id if guild else None), alert=True)
    elif risk >= 60 and cfg.quarantine_role_id and guild:
        role = guild.get_role(cfg.quarantine_role_id)
        if role:
            try:
                await user.add_roles(role, reason=f"보안 격리 - 위험도 {risk}")
            except Exception:
                pass
        await send_log(bot, cfg, f"⚠️ 격리: {user} | 위험 {risk}", guild_id=(guild.id if guild else None), alert=True)
    else:
        await send_log(bot, cfg, f"🔸 경고: {user} | 위험 {risk}", guild_id=(guild.id if guild else None))

# 이벤트 바인딩
def on_security_events_wireup(bot: commands.Bot, cfg: SecurityConfig):
    async def _ready():
        await bot.tree.sync()
        await send_log(bot, cfg, f"🛡️ 보안 모듈 준비 | 서버 {len(bot.guilds)}")
    bot.add_listener(_ready, "on_ready")

    @bot.event
    async def on_message(message: discord.Message):
        if message.author.bot:
            return
        uid = message.author.id
        now_ts = discord.utils.utcnow().timestamp()
        u = user_activity[uid]
        u["message_times"].append(now_ts)
        guild_id = message.guild.id if message.guild else None
        if cfg.enable_sqlite and await db_is_black_user(uid, cfg):
            try:
                await message.delete()
                await message.author.ban(reason="블랙리스트")
                await send_log(bot, cfg, f"🔥 블랙리스트 자동 차단: {message.author}", guild_id=guild_id, alert=True)
            except Exception:
                await send_log(bot, cfg, f"❌ 블랙리스트 처리 실패: {message.author}", guild_id=guild_id, alert=True)
            return
        risk = _calc_risk(uid, message, cfg)
        threats: List[str] = []
        mal_urls: Optional[List[dict]] = None
        if URL_REGEX.search(message.content):
            mal_urls = await extract_and_check_urls(message.content, cfg, guild_id=guild_id)
            if mal_urls:
                threats.extend([f"URL:{m['reason']}" for m in mal_urls])
                high = sum(1 for m in mal_urls if m["severity"] == "high")
                mid = sum(1 for m in mal_urls if m["severity"] == "medium")
                risk += high * RISK_WEIGHTS["url_high"] + mid * RISK_WEIGHTS["url_med"]
        if message.attachments:
            for f in message.attachments:
                fname = f.filename.lower()
                is_exec = any(fname.endswith(ext) for ext in [".exe", ".bat", ".cmd", ".scr"])
                if any(fname.endswith(ext) for ext in DANGEROUS_EXTS):
                    threats.append(f"파일확장자 의심:{f.filename}")
                    risk += int(RISK_WEIGHTS["danger_ext"] * 0.5)
                    if is_exec:
                        risk += int(RISK_WEIGHTS["danger_ext_exec_bonus"] * 0.5)
        recent10 = [t for t in u["message_times"] if now_ts - t < 10]
        if len(recent10) > cfg.spam_threshold_per_10s:
            threats.append("스팸10s")
            risk += RISK_WEIGHTS["spam_window"]
        if (len(message.mentions) + len(message.role_mentions)) > cfg.mention_threshold_per_msg:
            threats.append("멘션스팸")
            risk += RISK_WEIGHTS["mention_spam"]
        h = hashlib.md5(message.content.encode("utf-8", "ignore")).hexdigest()
        u["message_hashes"].append(h)
        if risk >= 40 or threats or mal_urls:
            await _moderate(bot, cfg, message, risk, threats, mal_urls)
        await bot.process_commands(message)

# 슬래시 명령 등록
def register_security_commands(bot: commands.Bot, cfg: SecurityConfig):
    // 이하 /보안상태, /setup_log, /setup_quarantine, /whitelist, /release 명령도
    // 동일한 스타일로 주석 처리 (각 명령어의 역할을 짧게 표기)

# 주기 정리 태스크
async def _periodic_cleanup():
    while True:
        try:
            now_ts = discord.utils.utcnow().timestamp()
            stale = [uid for uid, d in user_activity.items() if d["message_times"] and (now_ts - max(d["message_times"])) > 7*24*3600]
            for uid in stale:
                user_activity.pop(uid, None)
            LOGGER.info(f"🧹 정리 완료 | 비활성 사용자 {len(stale)}")
        except Exception:
            LOGGER.exception("정리 오류")
        await asyncio.sleep(3600)

# 백그라운드 태스크 시작
async def start_background_tasks(bot: commands.Bot, cfg: SecurityConfig):
    await db_init(cfg)
    global _http
    if cfg.enable_safe_browsing and aiohttp and _http is None:
        _http = aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=50))
    asyncio.create_task(_periodic_cleanup())
