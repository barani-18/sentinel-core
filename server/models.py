from sqlalchemy import Column, String, Float, DateTime
from datetime import datetime
from database import Base

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True, index=True)
    type = Column(String)
    severity = Column(String)
    status = Column(String, default="active") # active, resolved, ignored
    timestamp = Column(DateTime, default=datetime.utcnow)
    confidence = Column(Float)