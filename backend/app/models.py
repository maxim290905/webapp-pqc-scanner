from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Float, JSON, Enum as SQLEnum
from sqlalchemy.orm import relationship
from datetime import datetime
import enum
from app.database import Base


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    USER = "user"
    VIEWER = "viewer"


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class Severity(str, enum.Enum):
    P0 = "P0"  # Critical
    P1 = "P1"  # High
    P2 = "P2"  # Medium
    P3 = "P3"  # Low


class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(SQLEnum(UserRole), default=UserRole.USER)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    projects = relationship("Project", back_populates="owner")
    audit_logs = relationship("AuditLog", back_populates="user")


class Project(Base):
    __tablename__ = "projects"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    owner = relationship("User", back_populates="projects")
    scans = relationship("Scan", back_populates="project")


class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    target = Column(String, nullable=False)
    scan_type = Column(String, default="tls_network")
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.QUEUED)
    pq_score = Column(Float, nullable=True)
    report_path = Column(String, nullable=True)
    raw_json_path = Column(String, nullable=True)
    error_message = Column(Text, nullable=True)
    celery_task_id = Column(String, nullable=True)  # Store Celery task ID for progress tracking
    
    project = relationship("Project", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    asset_type = Column(String, nullable=False)  # cert, cipher, protocol, etc.
    detail_json = Column(JSON, nullable=False)
    severity = Column(SQLEnum(Severity), nullable=False)
    category = Column(String, nullable=False)  # deprecated_alg, weak_key, cert_expiry, etc.
    evidence = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    scan = relationship("Scan", back_populates="findings")
    recommendations = relationship("Recommendation", back_populates="finding", cascade="all, delete-orphan")


class Recommendation(Base):
    __tablename__ = "recommendations"
    
    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    priority = Column(SQLEnum(Severity), nullable=False)  # P0, P1, P2
    short_description = Column(Text, nullable=False)
    technical_steps = Column(Text, nullable=False)
    rollback_notes = Column(Text, nullable=True)
    verification_steps = Column(Text, nullable=False)
    effort_estimate = Column(String, nullable=False)  # Low, Medium, High or days
    confidence_score = Column(Integer, default=80)  # 0-100
    compliance_mapping = Column(Text, nullable=True)
    requires_privileged_action = Column(String, default="false")  # true/false
    status = Column(String, default="pending")  # pending, in_progress, resolved, rejected
    analyst_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    finding = relationship("Finding", back_populates="recommendations")
    scan = relationship("Scan")


class AuditLog(Base):
    __tablename__ = "audit_log"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String, nullable=False)
    details = Column(JSON, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User", back_populates="audit_logs")

