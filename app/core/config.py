from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    API_KEY: str = "test-key"
    PORT: int = 8000
    DATABASE_URL: str = "sqlite:///data/database.db"
    
    VT_API_KEY: str = ""
    SECURITYTRAILS_API_KEY: str = ""
    HUNTER_API_KEY: str = ""
    
    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
