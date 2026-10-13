from sqlalchemy import Text, Boolean, JSON, String, DateTime, Integer, BigInteger, ForeignKey
from sqlalchemy import func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from datetime import datetime

from src.db.engine import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    telegram_id: Mapped[int] = mapped_column(BigInteger, unique=True, index=True)
    username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    first_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now()
    )
    scans: Mapped[list["ScanRecord"]] = relationship(back_populates="user")

class ScanRecord(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    target_url: Mapped[str] = mapped_column(String(2048))
    ssl_valid: Mapped[bool] = mapped_column(Boolean, default=False)
    headers_score: Mapped[int] = mapped_column(Integer, default=0)
    has_leaks: Mapped[bool] = mapped_column(Boolean, default=False)
    has_html_issues: Mapped[bool] = mapped_column(Boolean, default=False)
    cookies_issues: Mapped[bool] = mapped_column(Boolean, default=False)
    raw_report: Mapped[dict] = mapped_column(JSON)
    ai_verdict: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now()
    )
    user: Mapped["User"] = relationship(back_populates="scans")