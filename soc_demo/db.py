"""
SQLite database for persistent storage.
Stores cases and approval decisions.
"""

from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, JSON, Boolean
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import datetime, timezone
from pathlib import Path

# Database file location
DB_PATH = Path(__file__).parent.parent / "data" / "app.db"

# Fix: Ensure the parent data/ directory exists before SQLite tries to write to it
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# Create engine
engine = create_engine(f'sqlite:///{DB_PATH}', echo=False)

# Base class for models
Base = declarative_base()

# Session maker
SessionLocal = sessionmaker(bind=engine)


def _utc_now():
    """Helper to return current UTC time, replacing deprecated datetime.utcnow()"""
    return datetime.now(timezone.utc)


class Case(Base):
    """
    Represents a security alert case.
    """
    __tablename__ = 'cases'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String, unique=True, nullable=False, index=True)
    alert_type = Column(String)
    severity = Column(String)
    hostname = Column(String)
    summary = Column(String)
    
    # Agent analysis results
    confidence_score = Column(Float)
    score_breakdown = Column(JSON)  # per-component breakdown, see scoring.ScoreBreakdown.as_dict()
    disposition = Column(String)
    mitre_mapping = Column(JSON)  # List of MITRE IDs
    decision_reasoning = Column(String)
    degraded_context = Column(Boolean, default=False)  # True if MITRE RAG retrieval failed for this case
    correlated_alert_count = Column(Integer, default=0)
    
    # Action proposal
    proposed_action = Column(String)
    action_parameters = Column(JSON)
    action_tier = Column(Integer)
    
    # Guardrail decision
    guardrail_decision = Column(String)
    
    # Human decision
    human_decision = Column(String)  # approved, rejected, pending
    human_decision_timestamp = Column(DateTime)
    human_decision_note = Column(String)
    
    # Audit trail
    audit_trail = Column(JSON)
    
    # Timestamps
    created_at = Column(DateTime, default=_utc_now)
    updated_at = Column(DateTime, default=_utc_now, onupdate=_utc_now)


def init_db():
    """Initialize the database (create tables)."""
    Base.metadata.create_all(engine)
    print(f"✅ Database initialized at {DB_PATH}")


def get_db():
    """Get a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


if __name__ == "__main__":
    # Initialize database
    init_db()