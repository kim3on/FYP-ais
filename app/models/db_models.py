from sqlalchemy import Column, String, Float, Boolean, Integer, JSON
from app.core.database import Base

class UserDB(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)
    role = Column(String)

class AlertDB(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String, unique=True, index=True)
    timestamp = Column(String)
    attack_type = Column(String)
    src_ip = Column(String)
    dst_ip = Column(String)
    dst_port = Column(Integer)
    protocol = Column(String)
    severity = Column(String)
    confidence = Column(Float)
    confidence_pct = Column(String)
    is_false_positive = Column(Boolean, default=False)
    is_zero_day = Column(Boolean, default=False)
    # Raw features can be stored as JSON
    raw_features = Column(JSON, nullable=True)

class BlockedIPDB(Base):
    __tablename__ = "blocked_ips"
    
    ip = Column(String, primary_key=True, index=True)
    blocked_at = Column(String)
    reason = Column(String)
    rule_name = Column(String)

class RawFlowDB(Base):
    __tablename__ = "raw_flows"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String, index=True)
    src_ip = Column(String)
    dst_ip = Column(String)
    dst_port = Column(Integer)
    protocol = Column(String)
    flow_bytes_s = Column(Float, nullable=True)
