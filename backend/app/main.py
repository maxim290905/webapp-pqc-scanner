from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from datetime import timedelta, datetime
from typing import List
import os

from app.database import get_db, engine, Base
from app.models import User, Scan, Project, Finding, AuditLog, UserRole, ScanStatus, Recommendation
from app.startup import init_db
from app.schemas import (
    Token, LoginRequest, UserCreate, UserResponse,
    ProjectCreate, ProjectResponse,
    ScanCreate, ScanResponse, ScanStatusResponse, ScanResultResponse, FindingResponse,
    AssetResponse, RecommendationResponse, RecommendationUpdate
)
from app.auth import (
    verify_password, get_password_hash, create_access_token,
    get_current_user
)
from app.config import settings
from app.celery_app import celery_app
from app.tasks import scan_task
from celery.result import AsyncResult
from app.report_generator import generate_pdf_report
from app.pq_score import calculate_pq_score

app = FastAPI(
    title="Cryptography Vulnerability Scanner API",
    description="API for automated TLS/certificate and network surface scanning",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    import asyncio
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, init_db)


@app.get("/")
async def root():
    return {"message": "Cryptography Vulnerability Scanner API", "version": "1.0.0"}


@app.get("/health")
async def health_check():
    return {"status": "healthy"}


# Auth endpoints
@app.post("/api/auth/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreate, db: Session = Depends(get_db)):
    """Register a new user"""
    # Check if user exists
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Create user
    user = User(
        email=user_data.email,
        name=user_data.name,
        password_hash=get_password_hash(user_data.password),
        role=user_data.role
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # Log action
    audit_log = AuditLog(
        user_id=user.id,
        action="user_registered",
        details={"email": user.email}
    )
    db.add(audit_log)
    db.commit()
    
    return user


@app.post("/api/auth/login", response_model=Token)
async def login(
    login_data: LoginRequest,
    db: Session = Depends(get_db)
):
    """Login and get access token"""
    user = db.query(User).filter(User.email == login_data.email).first()
    if not user or not verify_password(login_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(hours=settings.JWT_EXPIRATION_HOURS)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    
    # Log action
    audit_log = AuditLog(
        user_id=user.id,
        action="user_login",
        details={}
    )
    db.add(audit_log)
    db.commit()
    
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/api/auth/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information"""
    return current_user


# Project endpoints
@app.post("/api/projects", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_project(
    project_data: ProjectCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new project"""
    project = Project(
        name=project_data.name,
        owner_id=current_user.id
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    
    # Log action
    audit_log = AuditLog(
        user_id=current_user.id,
        action="project_created",
        details={"project_id": project.id, "project_name": project.name}
    )
    db.add(audit_log)
    db.commit()
    
    return project


@app.get("/api/projects", response_model=List[ProjectResponse])
async def list_projects(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all projects for current user"""
    projects = db.query(Project).filter(Project.owner_id == current_user.id).all()
    return projects


# Scan endpoints
@app.post("/api/scans", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    scan_data: ScanCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new scan task"""
    # Validate project exists and belongs to user
    project = db.query(Project).filter(
        Project.id == scan_data.project_id,
        Project.owner_id == current_user.id
    ).first()
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    
    # Basic target validation
    target = scan_data.target.strip()
    if not target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target cannot be empty"
        )
    
    # Check allowed targets if configured
    if settings.ALLOWED_TARGETS:
        allowed = [t.strip() for t in settings.ALLOWED_TARGETS.split(",")]
        if target not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Target not in allowed list"
            )
    
    # Create scan record
    scan = Scan(
        project_id=scan_data.project_id,
        target=target,
        scan_type=scan_data.scan_type,
        status=ScanStatus.QUEUED
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    # Queue Celery task and store task_id
    task = scan_task.delay(scan.id)
    scan.celery_task_id = task.id
    db.commit()
    
    # Log action
    audit_log = AuditLog(
        user_id=current_user.id,
        action="scan_created",
        details={"scan_id": scan.id, "target": target}
    )
    db.add(audit_log)
    db.commit()
    
    return scan


@app.get("/api/scans/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get scan status with progress"""
    scan = db.query(Scan).join(Project).filter(
        Scan.id == scan_id,
        Project.owner_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    # Get Celery task progress if scan is running
    progress = None
    if scan.status == ScanStatus.RUNNING and scan.celery_task_id:
        try:
            result = AsyncResult(scan.celery_task_id, app=celery_app)
            if result.state == 'PROGRESS':
                progress = result.info
        except Exception:
            # If we can't get progress, continue without it
            pass
    
    return ScanStatusResponse(
        id=scan.id,
        target=scan.target,
        status=scan.status,
        created_at=scan.created_at,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        error_message=scan.error_message,
        progress=progress
    )


@app.get("/api/scans/{scan_id}/result", response_model=ScanResultResponse)
async def get_scan_result(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get scan results"""
    scan = db.query(Scan).join(Project).filter(
        Scan.id == scan_id,
        Project.owner_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    if scan.status != ScanStatus.DONE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scan is not completed. Current status: {scan.status}"
        )
    
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    recommendations = db.query(Recommendation).filter(Recommendation.scan_id == scan_id).all()
    pq_score, pq_level = calculate_pq_score(findings)
    
    # Log action
    audit_log = AuditLog(
        user_id=current_user.id,
        action="scan_result_viewed",
        details={"scan_id": scan_id}
    )
    db.add(audit_log)
    db.commit()
    
    # Convert SQLAlchemy objects to Pydantic models
    scan_dict = {
        "id": scan.id,
        "project_id": scan.project_id,
        "target": scan.target,
        "scan_type": scan.scan_type,
        "status": scan.status,
        "pq_score": scan.pq_score,
        "created_at": scan.created_at,
        "started_at": scan.started_at,
        "finished_at": scan.finished_at,
    }
    
    findings_list = [
        {
            "id": f.id,
            "asset_type": f.asset_type,
            "detail_json": f.detail_json,
            "severity": f.severity,
            "category": f.category,
            "evidence": f.evidence,
        }
        for f in findings
    ]
    
    recommendations_list = [
        {
            "id": r.id,
            "finding_id": r.finding_id,
            "scan_id": r.scan_id,
            "priority": r.priority,
            "short_description": r.short_description,
            "technical_steps": r.technical_steps,
            "rollback_notes": r.rollback_notes,
            "verification_steps": r.verification_steps,
            "effort_estimate": r.effort_estimate,
            "confidence_score": r.confidence_score,
            "compliance_mapping": r.compliance_mapping,
            "requires_privileged_action": r.requires_privileged_action,
            "status": r.status,
            "analyst_notes": r.analyst_notes,
            "created_at": r.created_at,
            "updated_at": r.updated_at,
        }
        for r in recommendations
    ]
    
    return ScanResultResponse(
        scan=ScanResponse(**scan_dict),
        findings=[FindingResponse(**f) for f in findings_list],
        recommendations=[RecommendationResponse(**r) for r in recommendations_list],
        pq_score=pq_score,
        pq_level=pq_level,
        summary={
            "total_findings": len(findings),
            "by_severity": {
                "P0": sum(1 for f in findings if f.severity.value == "P0"),
                "P1": sum(1 for f in findings if f.severity.value == "P1"),
                "P2": sum(1 for f in findings if f.severity.value == "P2"),
                "P3": sum(1 for f in findings if f.severity.value == "P3"),
            }
        }
    )


@app.get("/api/scans/{scan_id}/report.pdf")
async def get_scan_report(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Download PDF report"""
    scan = db.query(Scan).join(Project).filter(
        Scan.id == scan_id,
        Project.owner_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    if scan.status != ScanStatus.DONE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scan is not completed. Current status: {scan.status}"
        )
    
    # Generate report if not exists
    report_path = scan.report_path
    if not report_path or not os.path.exists(report_path):
        os.makedirs(f"{settings.STORAGE_PATH}/reports", exist_ok=True)
        report_path = f"{settings.STORAGE_PATH}/reports/{scan_id}.pdf"
        findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        recommendations = db.query(Recommendation).filter(Recommendation.scan_id == scan_id).all()
        generate_pdf_report(scan, findings, recommendations, report_path)
        
        # Update scan record
        scan.report_path = report_path
        db.commit()
    
    # Log action
    audit_log = AuditLog(
        user_id=current_user.id,
        action="scan_report_downloaded",
        details={"scan_id": scan_id}
    )
    db.add(audit_log)
    db.commit()
    
    return FileResponse(
        report_path,
        media_type="application/pdf",
        filename=f"scan_{scan_id}_report.pdf"
    )


@app.get("/api/scans", response_model=List[ScanResponse])
async def list_scans(
    project_id: int = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all scans for current user"""
    query = db.query(Scan).join(Project).filter(Project.owner_id == current_user.id)
    
    if project_id:
        query = query.filter(Scan.project_id == project_id)
    
    scans = query.order_by(Scan.created_at.desc()).all()
    return scans


# Assets endpoint
@app.get("/api/assets", response_model=List[AssetResponse])
async def list_assets(
    project_id: int = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all scanned assets"""
    query = db.query(Scan).join(Project).filter(
        Project.owner_id == current_user.id,
        Scan.status == ScanStatus.DONE
    )
    
    if project_id:
        query = query.filter(Scan.project_id == project_id)
    
    scans = query.order_by(Scan.created_at.desc()).all()
    
    assets = []
    for scan in scans:
        findings_count = db.query(Finding).filter(Finding.scan_id == scan.id).count()
        assets.append(AssetResponse(
            target=scan.target,
            scan_id=scan.id,
            pq_score=scan.pq_score,
            status=scan.status,
            last_scan=scan.finished_at or scan.created_at,
            findings_count=findings_count
        ))
    
    return assets


# Recommendation endpoints
@app.put("/api/recommendations/{recommendation_id}", response_model=RecommendationResponse)
async def update_recommendation(
    recommendation_id: int,
    update_data: RecommendationUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update recommendation (analyst can edit)"""
    recommendation = db.query(Recommendation).join(Scan).join(Project).filter(
        Recommendation.id == recommendation_id,
        Project.owner_id == current_user.id
    ).first()
    
    if not recommendation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recommendation not found"
        )
    
    if update_data.technical_steps is not None:
        recommendation.technical_steps = update_data.technical_steps
    if update_data.effort_estimate is not None:
        recommendation.effort_estimate = update_data.effort_estimate
    if update_data.analyst_notes is not None:
        recommendation.analyst_notes = update_data.analyst_notes
    if update_data.status is not None:
        recommendation.status = update_data.status
    
    recommendation.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(recommendation)
    
    # Log action
    audit_log = AuditLog(
        user_id=current_user.id,
        action="recommendation_updated",
        details={"recommendation_id": recommendation_id}
    )
    db.add(audit_log)
    db.commit()
    
    rec_dict = {
        "id": recommendation.id,
        "finding_id": recommendation.finding_id,
        "scan_id": recommendation.scan_id,
        "priority": recommendation.priority,
        "short_description": recommendation.short_description,
        "technical_steps": recommendation.technical_steps,
        "rollback_notes": recommendation.rollback_notes,
        "verification_steps": recommendation.verification_steps,
        "effort_estimate": recommendation.effort_estimate,
        "confidence_score": recommendation.confidence_score,
        "compliance_mapping": recommendation.compliance_mapping,
        "requires_privileged_action": recommendation.requires_privileged_action,
        "status": recommendation.status,
        "analyst_notes": recommendation.analyst_notes,
        "created_at": recommendation.created_at,
        "updated_at": recommendation.updated_at,
    }
    
    return RecommendationResponse(**rec_dict)


@app.get("/api/scans/{scan_id}/recommendations/export")
async def export_recommendations(
    scan_id: int,
    format: str = "json",  # json, jira, github, csv
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Export recommendations in various formats"""
    scan = db.query(Scan).join(Project).filter(
        Scan.id == scan_id,
        Project.owner_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    recommendations = db.query(Recommendation).filter(Recommendation.scan_id == scan_id).all()
    
    if format == "json":
        return {
            "scan_id": scan_id,
            "target": scan.target,
            "recommendations": [
                {
                    "id": r.id,
                    "finding_id": r.finding_id,
                    "priority": r.priority.value,
                    "short_description": r.short_description,
                    "technical_steps": r.technical_steps,
                    "effort_estimate": r.effort_estimate,
                    "status": r.status,
                }
                for r in recommendations
            ]
        }
    elif format == "jira":
        # Jira JSON format
        issues = []
        for r in recommendations:
            issues.append({
                "fields": {
                    "project": {"key": "SEC"},  # Should be configurable
                    "summary": f"[{r.priority.value}] {r.short_description}",
                    "description": f"{r.technical_steps}\n\nEffort: {r.effort_estimate}\nConfidence: {r.confidence_score}%",
                    "issuetype": {"name": "Task"},
                    "priority": {"name": "High" if r.priority.value == "P0" else "Medium"},
                }
            })
        return {"issues": issues}
    elif format == "github":
        # GitHub issues format
        issues = []
        for r in recommendations:
            issues.append({
                "title": f"[{r.priority.value}] {r.short_description}",
                "body": f"## Technical Steps\n\n{r.technical_steps}\n\n## Effort Estimate\n{r.effort_estimate}\n\n## Verification Steps\n{r.verification_steps}",
                "labels": [r.priority.value, "security", "crypto"],
            })
        return {"issues": issues}
    elif format == "csv":
        # CSV format (return as JSON for now, can be converted to CSV in frontend)
        return {
            "headers": ["ID", "Priority", "Description", "Effort", "Status"],
            "rows": [
                [r.id, r.priority.value, r.short_description, r.effort_estimate, r.status]
                for r in recommendations
            ]
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported format: {format}"
        )

