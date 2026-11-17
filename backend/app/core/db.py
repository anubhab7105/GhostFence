"""Database connection helpers."""

from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from .settings import settings

engine = create_engine(settings.database_url, pool_pre_ping=True, future=True)


def get_session() -> Session:
    return Session(engine, future=True)


@contextmanager
def session_scope():
    session = get_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def ping() -> bool:
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    return True