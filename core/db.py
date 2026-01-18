import os
from sqlalchemy import create_engine, Column, Integer, String, Boolean, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

Base = declarative_base()


class RequestLog(Base):
    __tablename__ = 'request_logs'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    src_ip = Column(String)
    method = Column(String)
    path = Column(String)
    payload = Column(Text)
    status = Column(String) 
    ml_confidence = Column(String)
    soc_verdict = Column(String, nullable=True)

class AllowedPattern(Base):
    __tablename__ = 'allowed_patterns'
    id = Column(Integer, primary_key=True)
    method_path_hash = Column(String, unique=True)

class BlacklistRule(Base):
    __tablename__ = 'blacklist'
    id = Column(Integer, primary_key=True)
    rule_type = Column(String)
    value = Column(String)

DB_PATH = os.environ.get('DB_PATH', 'waf_data.db')

engine = create_engine(f'sqlite:///{DB_PATH}', connect_args={'check_same_thread': False})
Session = sessionmaker(bind=engine)
session = Session()

def init_db():
    Base.metadata.create_all(engine)