"""Unit of work for the Hunt Ledger.

One transaction boundary per iteration. The controller opens a unit of work,
does all of its reads and writes inside it, and commits once — so an iteration
either lands whole or not at all, and a crash mid-iteration cannot leave the
Ledger describing a half-applied decision.

The session factory is injectable: production passes the shared
``database.connection`` factory, tests pass a SQLite sessionmaker. Nothing
here imports the database at module scope, so importing the hunting package
never opens a connection.
"""

from __future__ import annotations

from typing import Callable, Optional

from sqlalchemy.orm import Session

from core.hunting.repository import HuntRepository

SessionFactory = Callable[[], Session]


def _default_session_factory() -> Session:
    from database.connection import get_db_session

    return get_db_session()


class HuntUnitOfWork:
    def __init__(self, session_factory: Optional[SessionFactory] = None):
        self._session_factory = session_factory or _default_session_factory
        self.session: Optional[Session] = None
        self.hunts: Optional[HuntRepository] = None

    def __enter__(self) -> "HuntUnitOfWork":
        self.session = self._session_factory()
        self.hunts = HuntRepository(self.session)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            if exc_type is not None:
                self.rollback()
        finally:
            if self.session is not None:
                self.session.close()
            self.session = None
            self.hunts = None

    def commit(self) -> None:
        if self.session is not None:
            self.session.commit()

    def rollback(self) -> None:
        if self.session is not None:
            self.session.rollback()
