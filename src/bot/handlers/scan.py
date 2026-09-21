from aiogram import Router
from aiogram.filters import Command, CommandObject
from aiogram.types import Message

from src.tasks import run_security_scan
from src.bot.formatters import format_scan_report, format_ai_report
from src.ai import ai_consultant
from src.db.engine import async_session
from src.db.crud import get_or_create_user, save_scan_record

router = Router(name="scan")


@router.message(Command("scan"))
async def cmd_scan(
    message: Message, 
    command: CommandObject
    ) -> None:
    async with async_session() as session:
        user = await get_or_create_user(
            session=session,
            telegram_id=message.from_user.id,
            username=message.from_user.username,
            firstname=message.from_user.first_name
        )

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

    async with async_session() as session:
        await save_scan_record(
            session=session,
            user_id=user.id,
            target_url=target_url,
            raw_report=report,
            ai_verdict=ai_report.verdict,
        )