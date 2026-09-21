from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db import User, ScanRecord

async def get_or_create_user(
    session: AsyncSession, 
    telegram_id: int, 
    username: str | None=None, 
    firstname: str | None=None
    ) -> User:
    existing_user = await session.scalar(select(User).where(User.telegram_id == telegram_id))

    if existing_user:
        if existing_user.username != username or existing_user.first_name != firstname:
            existing_user.username = username
            existing_user.first_name = firstname
            await session.commit()
            await session.refresh(existing_user)
        return existing_user
    
    new_user = User(
        telegram_id=telegram_id,
        username=username,
        first_name=firstname
    )

    session.add(new_user)
    await session.commit()
    await session.refresh(new_user)

    return new_user

async def save_scan_record(
    session: AsyncSession,
    user_id: int,
    target_url: str,
    raw_report: dict,
    ai_verdict: str
    ) -> ScanRecord:

    ssl_info = raw_report.get("ssl_report") or {}
    headers_info = raw_report.get("headers_report") or {}
    files_info = raw_report.get("files_report") or {}
    
    new_scan = ScanRecord(
        user_id=user_id,
        target_url=target_url,
        ssl_valid=ssl_info.get("is_valid", False),
        headers_score=int(headers_info.get("safety_percentage", 0)),
        has_leaks=files_info.get("has_leaks", False),
        raw_report=raw_report,
        ai_verdict=ai_verdict
    )

    session.add(new_scan)
    await session.commit()
    await session.refresh(new_scan)

    return new_scan

async def get_user_history(
    session: AsyncSession,
    telegram_id: int,
    limit=5
    ) -> list[ScanRecord]:
    query = (
        select(ScanRecord)
        .join(User)
        .where(User.telegram_id == telegram_id)
        .order_by(ScanRecord.created_at.desc())
        .limit(limit)
    )
    result = await session.scalars(query)
    return list(result.all())