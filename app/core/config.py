from pydantic_settings import BaseSettings
from pydantic import ConfigDict
from typing import Optional

class Settings(BaseSettings):
    API_KEY: str
    PORT: int = 8000
    DATABASE_URL: str = "sqlite:///data/database.db"

    VT_API_KEY: Optional[str] = None
    SECURITYTRAILS_API_KEY: Optional[str] = None
    HUNTER_API_KEY: Optional[str] = None

    model_config = ConfigDict(env_file=".env", extra="ignore")

settings = Settings()

