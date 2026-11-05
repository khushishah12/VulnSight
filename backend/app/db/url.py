"""Normalize a PostgreSQL URL for SQLAlchemy's asyncpg driver."""

from sqlalchemy.engine import make_url


def normalize_async_database_url(raw_url: str) -> str:
    """Return a ``postgresql+asyncpg://`` URL.

    Neon displays a ``postgresql://`` URL with query parameters such as
    ``sslmode`` and ``channel_binding``. Those are libpq/psql options, not
    asyncpg options, so they are removed here. TLS is supplied separately by
    the engine through an SSL context.
    """

    raw_url = raw_url.strip()
    if not raw_url:
        return ""

    if raw_url.startswith("postgres://"):
        raw_url = "postgresql://" + raw_url[len("postgres://") :]
    elif raw_url.startswith("postgresql://"):
        raw_url = "postgresql+asyncpg://" + raw_url[len("postgresql://") :]

    url = make_url(raw_url)
    ignored = {"sslmode", "ssl", "channel_binding"}
    query = {
        key: value
        for key, value in url.query.items()
        if key.lower() not in ignored
    }

    return url.set(drivername="postgresql+asyncpg", query=query).render_as_string(
        hide_password=False
    )
