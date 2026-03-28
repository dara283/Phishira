from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./phishara.db")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class ScanRecord(Base):
    __tablename__ = "scan_records"
    id = Column(Integer, primary_key=True, index=True)
    input_value = Column(String(2048), nullable=False)
    input_type = Column(String(20), nullable=False)  # url, email, phone
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(20), default="unknown")  # safe, low, medium, high, critical
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    ip_address = Column(String(64), nullable=True)


class ThreatIntelligence(Base):
    __tablename__ = "threat_intelligence"
    id = Column(Integer, primary_key=True, index=True)
    indicator = Column(String(2048), nullable=False, index=True)
    indicator_type = Column(String(20), nullable=False)
    threat_type = Column(String(100), nullable=True)
    source = Column(String(100), nullable=True)
    confidence = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)
