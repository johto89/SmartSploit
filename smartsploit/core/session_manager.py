"""
Session Manager - Manages exploit sessions and results
"""

import uuid
from datetime import datetime
from typing import Dict, List, Optional
from .framework import Target

class SessionManager:
    """Manages exploit sessions and results"""
    
    def __init__(self):
        self.sessions: Dict[str, Dict] = {}
        self.results: List[Dict] = []
        
    def create_session(self, target: Target, exploit: str) -> str:
        """Create new exploit session"""
        session_id = str(uuid.uuid4())[:8]
        self.sessions[session_id] = {
            "target": target,
            "exploit": exploit,
            "created_at": datetime.utcnow(),
            "status": "active"
        }
        return session_id
        
    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get session by ID"""
        return self.sessions.get(session_id)
        
    def close_session(self, session_id: str) -> bool:
        """Close active session"""
        if session_id in self.sessions:
            self.sessions[session_id]["status"] = "closed"
            return True
        return False
        
    def list_active_sessions(self) -> List[Dict]:
        """List all active sessions"""
        return [
            {"id": sid, **session} 
            for sid, session in self.sessions.items() 
            if session["status"] == "active"
        ]
        
    def get_session_count(self) -> int:
        """Get count of active sessions"""
        return len([s for s in self.sessions.values() if s["status"] == "active"])
