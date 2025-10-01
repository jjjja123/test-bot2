import asyncio, discord
from datetime import datetime
from .logging import LOGGER
from .db import db_init
from .clamav import init_clamav
from .rabbitmq import listen_scan_results
from .url_check import extract_and_check_urls
from .risk import user_activity

async def _periodic_cleanup():
    """오래된 사용자 활동 데이터 정리 (1시간마다 실행)"""
    while True:
        try:
            now_ts = discord.utils.utcnow().timestamp()
            stale = [
                uid for uid, d in user_activity.items()
                if d["message_times"] and (now_ts - max(d["message_times"])) > 7*24*3600
            ]
            for uid in stale:
                user_activity.pop(uid, None)
            if stale:
                LOGGER.info(f"🧹 정리 완료 | 비활성 사용자 {len(stale)} 제거")
        except Exception:
            LOGGER.exception("정리 오류")
        await asyncio.sleep(3600)

async def start_background_tasks(bot, cfg):
    """봇 실행 시 필요한 백그라운드 태스크 실행"""
    await db_init(cfg)

    if cfg.enable_clamav:
        await init_clamav()

    if cfg.enable_rabbitmq:
        asyncio.create_task(listen_scan_results(bot, cfg))

    asyncio.create_task(_periodic_cleanup())