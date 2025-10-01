import aio_pika, json
from datetime import datetime
from .logging import LOGGER

async def send_scan_task(file_path, guild_id, channel_id, user_id, cfg):
    if not (cfg.enable_rabbitmq and aio_pika):
        LOGGER.warning("RabbitMQ 비활성 상태, 요청 전송 안함")
        return
    try:
        connection = await aio_pika.connect_robust(cfg.rabbitmq_url)
        async with connection:
            channel = await connection.channel()
            queue = await channel.declare_queue("scan_requests", durable=True)
            payload = {
                "type": "file_scan",
                "guild_id": guild_id,
                "channel_id": channel_id,
                "user_id": user_id,
                "file_path": file_path,
                "timestamp": datetime.utcnow().isoformat()
            }
            await channel.default_exchange.publish(
                aio_pika.Message(body=json.dumps(payload).encode()),
                routing_key=queue.name
            )
            LOGGER.info(f"RabbitMQ 스캔 요청 전송: {payload}")
    except Exception:
        LOGGER.exception("RabbitMQ 전송 실패")

async def listen_scan_results(bot, cfg):
    if not (cfg.enable_rabbitmq and aio_pika):
        LOGGER.warning("RabbitMQ 비활성 상태, 응답 수신 안함")
        return
    try:
        connection = await aio_pika.connect_robust(cfg.rabbitmq_url)
        channel = await connection.channel()
        queue = await channel.declare_queue("scan_results", durable=True)

        async for message in queue:
            async with message.process():
                try:
                    result = json.loads(message.body)
                    guild = bot.get_guild(result["guild_id"])
                    channel_obj = bot.get_channel(result["channel_id"])
                    user = guild.get_member(result["user_id"]) if guild else None
                    bad = (result["result"] == "FOUND")
                    reason = result["reason"]
                    file_path = result["file_path"]

                    if bad and channel_obj:
                        await channel_obj.send(f"감염 파일 발견: `{file_path}` — {reason}")
                    elif channel_obj:
                        await channel_obj.send(f"안전 파일: `{file_path}`")

                except Exception:
                    LOGGER.exception("scan_results 처리 오류")
    except Exception:
        LOGGER.exception("RabbitMQ 응답 큐 연결 실패")