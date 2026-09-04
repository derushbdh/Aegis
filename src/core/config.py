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

    SCANNER_TIMEOUT: float=10.0
    SCANNER_USER_AGENT: str="Aegis-Security-Scanner (+https://github.com/derushbdh/Aegis)"

settings = Settings()