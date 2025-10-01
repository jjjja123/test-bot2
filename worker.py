import asyncio, aio_pika, json
from datetime import datetime
from core.logging import apply_logging
from core.config import SecurityConfig
from core.clamav import scan_attachment
from core.yara_scan import load_yara_rules, yara_scan

LOGGER = apply_logging()

cfg = SecurityConfig(
    log_channel_id=0,
    alert_channel_id=None,
    quarantine_role_id=None,
    enable_clamav=True,
    enable_rabbitmq=True
)

async def worker_loop():
    """RabbitMQ Worker: scan_requests 큐에서 메시지를 받아 파일 검사 후 scan_results 큐로 전송"""
    connection = await aio_pika.connect_robust(cfg.rabbitmq_url)
    async with connection:
        channel = await connection.channel()
        await channel.set_qos(prefetch_count=5)
        queue = await channel.declare_queue("scan_requests", durable=True)

        LOGGER.info("Worker 대기 시작 (scan_requests 큐)")

        async for message in queue:
            async with message.process():
                try:
                    task = json.loads(message.body)
                    if task.get("type") != "file_scan":
                        continue

                    file_path = task["file_path"]
                    guild_id = task["guild_id"]
                    channel_id = task["channel_id"]
                    user_id = task["user_id"]

                    # --- ClamAV 검사 ---
                    bad_clam, reason_clam = await scan_attachment(file_path)

                    # --- YARA 검사 ---
                    bad_yara, reason_yara = await yara_scan(file_path)

                    # 최종 판단
                    bad = bad_clam or bad_yara
                    reasons = []
                    if bad_clam: reasons.append(reason_clam)
                    if bad_yara: reasons.append(reason_yara)
                    reason_final = "; ".join(reasons) if reasons else "Clean"

                    result = {
                        "type": "scan_result",
                        "guild_id": guild_id,
                        "channel_id": channel_id,
                        "user_id": user_id,
                        "file_path": file_path,
                        "result": "FOUND" if bad else "CLEAN",
                        "engine": "ClamAV+YARA",
                        "reason": reason_final,
                        "timestamp": datetime.utcnow().isoformat()
                    }

                    # 결과 publish
                    await channel.default_exchange.publish(
                        aio_pika.Message(body=json.dumps(result).encode()),
                        routing_key="scan_results"
                    )

                    LOGGER.info(f"[Worker] 검사 완료: {file_path} → {result['result']} ({reason_final})")

                except Exception as e:
                    LOGGER.exception(f"Worker 처리 오류: {e}")

if __name__ == "__main__":
    try:
        # 시작 시 YARA 룰 로드
        load_yara_rules("./yara_rules")
        asyncio.run(worker_loop())
    except KeyboardInterrupt:
        LOGGER.info("Worker 종료")