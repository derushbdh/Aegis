from aiogram import Router
from aiogram.filters import Command, CommandStart
from aiogram.types import Message

router = Router(name="common")

@router.message(CommandStart())
async def cmd_start(message: Message) -> None:
    await message.answer(
        "🛡 <b>Добро пожаловать в Aegis Security Scanner!</b>\n\n"
        "Я провожу автоматический black-box аудит безопасности веб-сайтов:\n"
        "• Проверка SSL/TLS сертификата и срока действия\n"
        "• Анализ критических заголовков безопасности (HSTS, CSP, etc.)\n"
        "• Поиск утечек конфиденциальных файлов (.env, .git, etc.)\n\n"
        "Чтобы запустить аудит, отправь команду:\n"
        "<code>/scan https://example.com</code>"
    )

@router.message(Command("help"))
async def cmd_help(message: Message) -> None:
    await message.answer(
        "📖 <b>Как пользоваться сканером:</b>\n\n"
        "• <code>/scan &lt;url&gt;</code> — быстрый запуск проверки целевого хоста\n"
        "• <code>/help</code> — это справочное сообщение"
    )