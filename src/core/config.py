from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import SecretStr

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    APP_NAME: str="Aegis"
    DEBUG: bool=True
    ENVIRONMENT: str="development"

    BOT_TOKEN: SecretStr

    REDIS_URL: str = "redis://localhost:6379/0"

    SCANNER_TIMEOUT: float=10.0
    SCANNER_USER_AGENT: str="Aegis-Security-Scanner (+https://github.com/derushbdh/Aegis)"

    AI_BASE_URL: str = "http://localhost:1234/v1"
    AI_API_KEY: str = "lm-studio"
    AI_MODEL: str = "qwen2.5-coder-7b-instruct"

    DB_HOST: str
    DB_PORT: int
    DB_USER: str
    DB_PASSWORD: str
    DB_NAME: str

    @property
    def get_database_url(self):
        return f"postgresql+asyncpg://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"

settings = Settings()