from tokenly.database import DatabaseManager

# Initialize DatabaseManager with SQLite
db_manager = DatabaseManager("sqlite:///./tokenly.db")

def init_db():
    db_manager.create_tables()

def get_db():
    with db_manager.get_session() as session:
        yield session
