"""Bootstrap only the network-isolated, disposable owner database."""
import os
import uuid
from sqlalchemy import create_engine,text
from sqlalchemy.orm import Session
from controlplane_db.migrations import upgrade
from controlplane_db.models import Tenant

url='postgresql+psycopg://postgres:'+os.environ['POSTGRES_PASSWORD']+'@127.0.0.1:5432/postgres'
upgrade(url)
engine=create_engine(url)
password=os.environ['RUNTIME_DB_PASSWORD']
assert len(password)==32 and all(c in '0123456789abcdef' for c in password)
with engine.begin() as connection:
    connection.execute(text("CREATE ROLE api_keys_fixture_runtime LOGIN PASSWORD '"+password+"' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE"))
    connection.execute(text('GRANT USAGE ON SCHEMA public TO api_keys_fixture_runtime'))
    connection.execute(text('GRANT SELECT ON ALL TABLES IN SCHEMA public TO api_keys_fixture_runtime'))
    connection.execute(text('GRANT INSERT,UPDATE ON api_keys TO api_keys_fixture_runtime'))
with Session(engine) as session:
    session.add_all([Tenant(id=uuid.UUID(os.environ[name]),name='isolated-api-key-runtime',is_active=True)
                     for name in ('FIXTURE_TENANT','FIXTURE_OTHER_TENANT')])
    session.commit()
engine.dispose()
print('Disposable owner schema and runtime role ready')
