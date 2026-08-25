import os
from dotenv import load_dotenv
load_dotenv()
from sqlalchemy import create_engine, text

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("No DATABASE_URL found in env")

print(f"Connecting to {DATABASE_URL}")
engine = create_engine(DATABASE_URL)
with engine.connect() as conn:
    conn.execute(text("DROP TABLE IF EXISTS evidence_artifacts CASCADE;"))
    conn.commit()
print("Dropped evidence_artifacts table successfully.")
