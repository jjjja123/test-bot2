import re, urllib.parse, asyncio
import discord
from .db import db_is_black_domain, db_add_black_domain, db_url_inc
from datetime import datetime
from zoneinfo import ZoneInfo

TZ = ZoneInfo("Asia/Seoul")

URL_REGEX = re.compile(r"https?://[^\s<>()]+")
SAFE_DOMAINS = (
    "youtube.com", "youtu.be", "google.com", "github.com",
    "wikipedia.org", "reddit.com", "discord.com", "discordapp.com",
)
SUSPICIOUS_DOMAIN_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r".*discord.*nitro.*", r".*steam.*gift.*", r"bit\.ly", r"tinyurl\.com", r"t\.co"
]]

async def _pattern_url_bad(url: str, cfg, guild_id=None):
    try:
        p = urllib.parse.urlparse(url)
        domain = p.netloc.lower()
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

async def extract_and_check_urls(text: str, cfg):
    urls = URL_REGEX.findall(text)
    out = []
    for u in urls:
        if not u.startswith(("http://", "https://")):
            u = "https://" + u
        bad, reason = await _pattern_url_bad(u, cfg)
        if bad:
            sev = "high" if "phishing" in reason.lower() else "medium"
            out.append({"url": u, "reason": reason, "severity": sev})
            if cfg.enable_sqlite and not any(sd in urllib.parse.urlparse(u).netloc.lower() for sd in SAFE_DOMAINS):
                await db_add_black_domain(urllib.parse.urlparse(u).netloc.lower(), cfg)
    return out