from sqlmodel import create_engine, SQLModel, Session
from typing import Generator

class DatabaseManager:
    def __init__(self, db_url: str):
        self.engine = create_engine(db_url, connect_args={"check_same_thread": False})

    def init_db(self):
        SQLModel.metadata.create_all(self.engine)

    def get_session(self) -> Generator[Session, None, None]:
        with Session(self.engine) as session:
            yield session

# Initialize DatabaseManager with SQLite
db_manager = DatabaseManager("sqlite:///./tokenly.db")

def init_db():
    db_manager.init_db()

def get_db():
    yield from db_manager.get_session()
