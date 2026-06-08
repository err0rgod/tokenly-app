from tokenly.database import DatabaseManager

# Initialize DatabaseManager with SQLite
db_manager = DatabaseManager("sqlite:///./tokenly.db")

def init_db():
    db_manager.init_db()

def get_db():
    yield from db_manager.get_session()
