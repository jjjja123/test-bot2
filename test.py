
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
    raise ValueError("❌ BOT_TOKEN이 .env에서 로드되지 않았습니다.")

# 포트 체크
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

# 포트 체크

MCHID = 1131597349391712432
TCHID = 1131597349391712433

intents = discord.Intents.all()


intents.message_content = True
intents.members = True

class MyBot(commands.Bot):
    def __init__(self, **kwargs):
        super().__init__(command_prefix='!', intents=intents, **kwargs)
        self.synced = False
        
    async def on_ready(self):
        print(f'봇이 로그인되었습니다: {self.user.name}')
        if not self.synced:
            await self.tree.sync()
            print("슬래시 명령어가 동기화되었습니다.")
            self.synced = True
        tracemalloc.start()

    async def on_message(self, message):
        if message.author.bot:
            return
        if message.content == "핑":
            await message.channel.send("퐁")

bot = MyBot()




@bot.tree.command(name='안녕', description="봇한테 인사를 합니다")
async def 안녕(interaction: discord.Interaction):
    await interaction.response.send_message("안녕하세요")

async def main():
    async with bot:
        await bot.start(TOKEN)

import asyncio
asyncio.run(main())




