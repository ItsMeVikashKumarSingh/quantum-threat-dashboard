from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
import datetime

DATABASE_URL = "sqlite:///./threat_dashboard.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class ScannedAsset(Base):
    __tablename__ = "scanned_assets"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    asset_type = Column(String)
    detected_algorithm = Column(String)
    key_size = Column(Integer, nullable=True)
    threat_level = Column(String)
    date_scanned = Column(DateTime, default=datetime.datetime.utcnow)
    
    migrations = relationship("MigrationHistory", back_populates="asset", cascade="all, delete-orphan")

class MigrationHistory(Base):
    __tablename__ = "migration_history"
    
    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("scanned_assets.id"))
    target_algorithm = Column(String)
    operator = Column(String, default="System Administrator")
    migration_status = Column(String, default="Pending")
    date_migrated = Column(DateTime, default=datetime.datetime.utcnow)
    
    asset = relationship("ScannedAsset", back_populates="migrations")

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
