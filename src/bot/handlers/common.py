from aiogram import Router
from aiogram.filters import Command, CommandStart
from aiogram.types import Message

router = Router(name="common")

@router.message(CommandStart())
async def cmd_start(message: Message) -> None:
    await message.answer(
        "🛡 <b>Welcome to Aegis Security Scanner!</b>\n\n"
        "I perform automated black-box website security audits:\n"
        "• SSL/TLS certificate validation and expiration checks\n"
        "• Security headers analysis (HSTS, CSP, etc.)\n"
        "• Sensitive file leak detection (.env, .git, etc.)\n"
        "• HTML markup vulnerability scanning (forms, comments, links)\n"
        "• Cookie security configuration audit (HttpOnly, Secure, SameSite)\n\n"
        "To start an audit, send the command:\n"
        "<code>/scan https://example.com</code>"
    )

@router.message(Command("help"))
async def cmd_help(message: Message) -> None:
    await message.answer(
        "📖 <b>How to use the scanner:</b>\n\n"
        "• <code>/scan &lt;url&gt;</code> — run a security audit on the target host\n"
        "• <code>/help</code> — show this help message\n"
        "• <code>/history</code> — view your recent scan history"
    )