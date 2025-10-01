import discord
from datetime import datetime
from zoneinfo import ZoneInfo
from .logging import LOGGER

TZ = ZoneInfo("Asia/Seoul")

async def try_add_reaction(message: discord.Message, emoji: str):
    try:
        await message.add_reaction(emoji)
        return True
    except Exception:
        return False

async def send_log(bot, cfg, message: str, *, guild_id=None, alert=False):
    LOGGER.info(("ALERT: " if alert else "LOG: ") + message)
    channel_id = cfg.alert_channel_id if (alert and cfg.alert_channel_id) else cfg.log_channel_id
    ch = bot.get_channel(channel_id)
    if not ch:
        return
    try:
        if alert:
            embed = discord.Embed(title="보안 경고", description=message, color=0xFF0000, timestamp=datetime.now(TZ))
            embed.set_footer(text="Security Bot")
            await ch.send(embed=embed)
        else:
            await ch.send(f"`{message}`")
    except Exception:
        LOGGER.exception("send_log 오류")

async def _moderate(bot, cfg, message: discord.Message, risk: int, threats: list, mal_urls=None):
    user = message.author
    try:
        await message.delete()
    except Exception:
        pass
    if not cfg.auto_ban_enabled:
        await send_log(bot, cfg, f"경고: {user} | 위험 {risk} | 위협 {', '.join(threats) if threats else '-'}")
        return
    if risk >= 80:
        try:
            await user.ban(reason=f"자동 차단 - 위험 {risk}")
            await send_log(bot, cfg, f"자동 차단: {user} | 위험 {risk}", alert=True)
        except discord.Forbidden:
            await send_log(bot, cfg, f"차단 권한 부족: {user}", alert=True)
    elif risk >= 60 and cfg.quarantine_role_id:
        role = message.guild.get_role(cfg.quarantine_role_id)
        if role:
            try:
                await user.add_roles(role, reason=f"보안 격리 - 위험 {risk}")
            except Exception:
                pass
        await send_log(bot, cfg, f"격리: {user} | 위험 {risk}", alert=True)

    # 경고 정책
    else:
        await send_log(bot, cfg, f"경고: {user} | 위험 {risk}")