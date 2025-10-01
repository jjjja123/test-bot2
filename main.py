import discord, asyncio, tracemalloc, os, threading, socket
from discord.ext import commands
from dotenv import load_dotenv

# .env 로드
load_dotenv()
TOKEN = os.getenv("BOT_TOKEN")
if TOKEN is None:
    raise ValueError("❌ BOT_TOKEN이 .env에서 로드되지 않았습니다.")

# Health 체크 서버
def run_health_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", 8000))
    s.listen(1)
    while True:
        conn, addr = s.accept()
        conn.close()

threading.Thread(target=run_health_server, daemon=True).start()

# Intents
intents = discord.Intents.all()
intents.message_content = True
intents.members = True

# core에서 필요한 보안 기능 가져오기
from core import (
    apply_logging,
    load_config,
    register_security_commands,
    start_background_tasks,
)

class MyBot(commands.Bot):
    def __init__(self, **kwargs):
        super().__init__(command_prefix="!", intents=intents, **kwargs)
        self.synced = False
        self.cfg = None
        self.logger = None

    async def on_ready(self):
        print(f"봇 로그인 완료: {self.user.name}")

        if self.logger is None:
            self.logger = apply_logging()
        if self.cfg is None:
            self.cfg = load_config()
            register_security_commands(self, self.cfg)
            await start_background_tasks(self, self.cfg)

        if not self.synced:
            await self.tree.sync()
            print("✅ 슬래시 명령어 동기화 완료")
            self.synced = True

        tracemalloc.start()

# 봇 인스턴스
bot = MyBot()

# Ping Pong 커맨드
@bot.command(name="ping")
async def ping_cmd(ctx: commands.Context):
    await ctx.send("퐁")

# 실행부
async def main():
    await bot.start(TOKEN)

if __name__ == "__main__":
    asyncio.run(main())
