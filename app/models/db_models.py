from sqlalchemy import Column, String, Float, Boolean, Integer, JSON, ForeignKey
from sqlalchemy.orm import relationship
from app.core.database import Base

class UserDB(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)
    role = Column(String)
    profile = relationship("UserProfileDB", back_populates="user", uselist=False, cascade="all, delete-orphan")

class UserProfileDB(Base):
    __tablename__ = "user_profiles"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False, index=True)
    display_name = Column(String)
    email = Column(String)
    phone = Column(String)
    job_title = Column(String)
    soc_tier = Column(String)
    team = Column(String)
    shift = Column(String)
    timezone = Column(String)
    escalation_contact = Column(String)

    user = relationship("UserDB", back_populates="profile")

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
    traffic_direction = Column(String, nullable=True)
    flow_initiator_ip = Column(String, nullable=True)
    flow_responder_ip = Column(String, nullable=True)
    local_ip = Column(String, nullable=True)
    remote_ip = Column(String, nullable=True)
    suspected_attacker_ip = Column(String, nullable=True)
    suspected_victim_ip = Column(String, nullable=True)
    suspected_compromised_host = Column(String, nullable=True)
    containment_target_ip = Column(String, nullable=True)
    endpoint_role_confidence = Column(String, nullable=True)
    endpoint_role_reason = Column(String, nullable=True)
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
