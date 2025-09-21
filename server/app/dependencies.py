from typing import Generator
from sqlalchemy.orm import Session
from database import get_session

def get_db() -> Generator[Session, None, None]:
    """Dependency to get database session."""
    session = get_session()
    try:
        yield session
    finally:
        session.close()
