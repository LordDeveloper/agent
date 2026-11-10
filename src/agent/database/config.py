from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote_plus

from agent.config import AgentSettings


@dataclass(frozen=True, slots=True)
class DatabaseConfig:
    connection: str
    host: str
    port: int
    database: str
    username: str
    password: str
    sqlite_path: Path | None = None
    data_dir: Path | None = None

    @property
    def dialect(self) -> str:
        return self.connection.strip().lower()

    @property
    def is_sqlite(self) -> bool:
        return self.dialect in ("sqlite", "")

    @property
    def is_mysql(self) -> bool:
        return self.dialect in ("mysql", "mariadb")

    def migration_lock_path(self) -> Path:
        base = self.data_dir or (
            self.sqlite_path.parent if self.sqlite_path is not None else Path("/var/lib/agent")
        )
        if self.is_sqlite and self.sqlite_path is not None:
            return self.sqlite_path.with_name(self.sqlite_path.name + ".migrate.lock")
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in self.database)[:64]
        return Path(base) / f"{safe}.migrate.lock"

    def sqlalchemy_async_url(self) -> str:
        if self.is_sqlite:
            if self.sqlite_path is None:
                raise RuntimeError("sqlite_path is required for sqlite connections")
            return f"sqlite+aiosqlite:///{self.sqlite_path.resolve().as_posix()}"
        if self.is_mysql:
            user = quote_plus(self.username)
            password = quote_plus(self.password)
            host = self.host or "127.0.0.1"
            port = int(self.port or 3306)
            db = quote_plus(self.database)
            return f"mysql+aiomysql://{user}:{password}@{host}:{port}/{db}"
        raise RuntimeError(f"unsupported DB_CONNECTION={self.connection!r}")

    def status_label(self) -> str:
        if self.is_sqlite and self.sqlite_path is not None:
            return str(self.sqlite_path)
        host = self.host or "127.0.0.1"
        port = int(self.port or 3306)
        return f"{self.dialect}://{host}:{port}/{self.database}"

    def alembic_sync_url(self) -> str:
        """Sync URL for Alembic (sqlite migrations only)."""
        if self.is_sqlite:
            if self.sqlite_path is None:
                raise RuntimeError("sqlite_path is required")
            return f"sqlite:///{self.sqlite_path.resolve().as_posix()}"
        if self.is_mysql:
            user = quote_plus(self.username)
            password = quote_plus(self.password)
            host = self.host or "127.0.0.1"
            port = int(self.port or 3306)
            db = quote_plus(self.database)
            return f"mysql+pymysql://{user}:{password}@{host}:{port}/{db}"
        raise RuntimeError(f"unsupported DB_CONNECTION={self.connection!r}")


def database_config_from_settings(settings: AgentSettings) -> DatabaseConfig:
    connection = (settings.db_connection or "sqlite").strip().lower()
    sqlite_path = settings.resolve_db_path() if connection in ("sqlite", "") else None
    database = (settings.db_database or "").strip() or (
        "agent.db" if connection in ("sqlite", "") else ""
    )
    if settings.db_connection.strip().lower() in ("mysql", "mariadb") and not database:
        raise ValueError("DB_DATABASE is required when DB_CONNECTION=mysql")
    return DatabaseConfig(
        connection=connection,
        host=(settings.db_host or "127.0.0.1").strip(),
        port=int(settings.db_port or 3306),
        database=database,
        username=(settings.db_username or "").strip(),
        password=settings.db_password or "",
        sqlite_path=sqlite_path,
        data_dir=Path(settings.data_dir),
    )


def database_status_from_settings(settings: AgentSettings) -> str:
    return database_config_from_settings(settings).status_label()


def database_config_from_path(path: str | Path) -> DatabaseConfig:
    resolved = Path(path).resolve()
    return DatabaseConfig(
        connection="sqlite",
        host="127.0.0.1",
        port=3306,
        database=resolved.name,
        username="",
        password="",
        sqlite_path=resolved,
        data_dir=resolved.parent,
    )
