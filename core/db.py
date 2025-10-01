import aiosqlite
from datetime import datetime
from zoneinfo import ZoneInfo

TZ = ZoneInfo("Asia/Seoul")
DB_PATH = "security.db"

CREATE_SQL = """
CREATE TABLE IF NOT EXISTS blacklist_users(user_id INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS blacklist_domains(domain TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS url_stats(day TEXT PRIMARY KEY, total_checked INTEGER NOT NULL DEFAULT 0, malicious_found INTEGER NOT NULL DEFAULT 0);
"""

async def db_init(cfg):
    if not cfg.enable_sqlite or not aiosqlite:
        return
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(CREATE_SQL)
        await db.commit()

async def db_add_black_user(uid: int, cfg):
    if not (cfg.enable_sqlite and aiosqlite):
        return
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("INSERT OR IGNORE INTO blacklist_users(user_id) VALUES(?)", (uid,))
        await db.commit()

async def db_is_black_user(uid: int, cfg) -> bool:
    if not (cfg.enable_sqlite and aiosqlite):
        return False
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT 1 FROM blacklist_users WHERE user_id=?", (uid,)) as cur:
            return (await cur.fetchone()) is not None

async def db_add_black_domain(domain: str, cfg):
    if not (cfg.enable_sqlite and aiosqlite):
        return
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("INSERT OR IGNORE INTO blacklist_domains(domain) VALUES(?)", (domain,))
        await db.commit()

async def db_is_black_domain(domain: str, cfg) -> bool:
    if not (cfg.enable_sqlite and aiosqlite):
        return False
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT 1 FROM blacklist_domains WHERE domain=?", (domain,)) as cur:
            return (await cur.fetchone()) is not None

async def db_url_inc(total=0, bad=0, cfg=None):
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