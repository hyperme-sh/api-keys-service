"""Create only an owned, disposable PostgreSQL instance; never accept a live URL."""
import subprocess
import time
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
from controlplane_db.migrations import upgrade


@pytest.fixture(scope="session")
def lifecycle_database():
    name = "api-key-membership-" + uuid.uuid4().hex
    password = uuid.uuid4().hex
    subprocess.run(["docker", "run", "--detach", "--name", name,
                    "--publish", "127.0.0.1::5432", "--env", "POSTGRES_PASSWORD=" + password,
                    "postgres:16-alpine"], check=True, capture_output=True)
    try:
        port = subprocess.check_output(["docker", "port", name, "5432/tcp"], text=True).strip().rsplit(":", 1)[1]
        url = f"postgresql+psycopg://postgres:{password}@127.0.0.1:{port}/postgres"
        # The image's temporary initialization server is socket-only. Probe the
        # published TCP endpoint used by migrations, not an in-container socket.
        probe = create_engine(url, connect_args={"connect_timeout": 1})
        try:
            deadline = time.monotonic() + 60
            while True:
                try:
                    with probe.connect() as connection:
                        connection.execute(text("SELECT 1"))
                    break
                except OperationalError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Disposable PostgreSQL TCP endpoint did not become ready") from None
                    time.sleep(1)
        finally:
            probe.dispose()
        upgrade(url)
        yield url.replace("postgresql+psycopg://", "postgresql+asyncpg://")
    finally:
        subprocess.run(["docker", "rm", "--force", "--volumes", name], check=True, capture_output=True)
