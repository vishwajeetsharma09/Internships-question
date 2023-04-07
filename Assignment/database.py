from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
#from sqlalchemy import SQLAlchemy
#db = sqlalchemy.SQLAlchemy(engine)
from flask_sqlalchemy import SQLAlchemy



db = SQLAlchemy("sqlite:///./test.db")


SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
