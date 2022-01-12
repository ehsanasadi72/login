from pydantic import BaseModel, Field


class AuthModel(BaseModel):
    username: str = Field(...)
    password: str = Field(...)
