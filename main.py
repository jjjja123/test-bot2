import discord
from discord.ext import commands, tasks
from discord import app_commands, ButtonStyle, Interaction, ui
import datetime
from datetime import datetime
import pytz
import tracemalloc
import random
import asyncio
import json
import os

from dotenv import load_dotenv
load_dotenv()

TOKEN = os.getenv('BOT_TOKEN')
if TOKEN is None:
    raise ValueError(" BOT_TOKEN이 .env에서 로드되지 않았습니다.")

#  Health 체크 서버 
import threading
import socket

def run_health_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", 8000))
    s.listen(1)
    while True:
        conn, addr = s.accept()
        conn.close()

threading.Thread(target=run_health_server, daemon=True).start()

# 채널 상수
MCHID = 1375120898473853098
TCHID = 1416614278969950330

# Intents
intents = discord.Intents.all()
intents.message_content = True
intents.members = True

# 보안 코어 주입을 위한 import 
# - 보안 로깅/슬래시 명령/이벤트 바인딩/백그라운드 태스크는 코어에서 담당
from security_core import (
    apply_logging,
    load_config,
    register_security_commands,
    on_security_events_wireup,
    start_background_tasks,
)

class MyBot(commands.Bot):
    def __init__(self, **kwargs):
        super().__init__(command_prefix='!', intents=intents, **kwargs)
        self.synced = False
        # (추가) 코어 설정/로거 보관
        self.cfg = None
        self.logger = None
        
    async def on_ready(self):
        print(f'봇이 로그인되었습니다: {self.user.name}')

        # (추가) 최초 1회에 한해 코어 초기화/바인딩
        if self.logger is None:
            self.logger = apply_logging()        # 로테이팅 파일 로그 + 콘솔
        if self.cfg is None:
            self.cfg = load_config()             # .env 플래그 로드(보수적 기본)

            # 보안 이벤트/명령 주입
            on_security_events_wireup(self, self.cfg)
            register_security_commands(self, self.cfg)
            await start_background_tasks(self, self.cfg)  # DB 초기화/정리 태스크/HTTP 세션 등

        if not self.synced:
            await self.tree.sync()
            print("슬래시 명령어가 동기화되었습니다.")
            self.synced = True

        # 메모리 추적 시작
        tracemalloc.start()

    # 아래 원본 on_message 구현은 충돌을 피하기 위해 제외/주석 처리합니다.
    # async def on_message(self, message):
    #     if message.author.bot:
    #         return
    #     if message.content == "핑":
    #         await message.channel.send("퐁")

# 인스턴스 생성 (원본 유지)
bot = MyBot()

# ===== (대체) 핑퐁은 on_message 대신 커맨드로 제공하여 충돌 방지 =====
@bot.command(name="ping")
async def ping_cmd(ctx: commands.Context):
    await ctx.send("퐁")
#

# (실행부)
async def main():
    await bot.start(TOKEN)

if __name__ == "__main__":
    asyncio.run(main())
