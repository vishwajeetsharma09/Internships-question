from pydantic import BaseModel
#from app import db


class User(BaseModel):
    email: str
    password: str
