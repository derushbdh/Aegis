from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message

from src.db.engine import async_session
from src.db.crud import get_user_history
from src.bot.formatters import format_history_report

router = Router(name="history")


@router.message(Command("history"))
async def cmd_history(message: Message) -> None:
    async with async_session() as session:
        history = await get_user_history(session, telegram_id=message.from_user.id, limit=5)
    # Check if history is empty
    if not history:
        await message.answer(
            "📭 <b>You don't have any audits yet.</b>\n\n"
        )
        return

    response_text = format_history_report(history)
    await message.answer(response_text)