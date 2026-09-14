from aiogram import Router
from aiogram.filters import Command, CommandObject
from aiogram.types import Message

from src.tasks import run_security_scan
from src.bot.formatters import format_scan_report, format_ai_report
from src.ai import ai_consultant

router = Router(name="scan")


@router.message(Command("scan"))
async def cmd_scan(message: Message, command: CommandObject) -> None:
    target_url = command.args
    if target_url is None:
        await message.answer("Укажите URL: /scan https://example.com")
        return
    
    if not target_url.startswith(("http://", "https://")):
        target_url = f"https://{target_url}"
    
    status_msg = await message.answer("🔍 Запускаю аудит безопасности...")

    report = await run_security_scan(target_url)
    response_text = format_scan_report(report)
    await status_msg.edit_text(response_text)

    ai_status_msg = await message.answer("🤖 AI-консультант изучает риски...")
    ai_report = await ai_consultant.analyze_scan(report)
    await ai_status_msg.edit_text(format_ai_report(ai_report))