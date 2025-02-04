from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    database_hostname : str
    database_port : str
    database_name : str
    database_username : str 
    database_password : str 
    secret_key: str # createdUsing openssl rand -hex 32
    algorithm: str
    access_token_expire_minutes: int
    refresh_token_expire_days: int
    admin_user: str
    admin_password: str
    admin_email: str

    # class Config:
    #     env_file = ".env"
    model_config = SettingsConfigDict(env_file=".env") 

settings = Settings()
