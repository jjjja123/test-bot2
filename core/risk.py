import discord, hashlib
from collections import defaultdict, deque
from datetime import datetime
from zoneinfo import ZoneInfo

TZ = ZoneInfo("Asia/Seoul")

RISK_WEIGHTS = {
    "new_account_1d": 40,
    "new_account_ndays": 25,
    "fast_msgs_high": 30,
    "fast_msgs_mid": 20,
    "dup_msg": 25,
    "server_attack": 50,
    "phishing": 40,
    "channel_hopping": 20,
    "mention_over": 15,
    "danger_ext": 60,
    "danger_ext_exec_bonus": 40,
    "spam_window": 25,
    "mention_spam": 20,
    "url_high": 50,
    "url_med": 30,
    "url_low": 20,
}

user_activity = defaultdict(lambda: {
    "message_times": deque(maxlen=20),
    "message_hashes": deque(maxlen=10),
    "reaction_times": deque(maxlen=15),
    "warnings": 0,
    "risk_score": 0,
    "last_channel_ids": deque(maxlen=5),
    "voice_hops": deque(maxlen=10),
})
server_activity = defaultdict(lambda: {
    "channel_creations": deque(maxlen=20),
    "role_creations": deque(maxlen=20),
    "mass_bans": deque(maxlen=10),
    "webhook_creations": deque(maxlen=15),
    "invite_creations": deque(maxlen=30),
})

def _calc_risk(user_id: int, msg: discord.Message, cfg) -> int:
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