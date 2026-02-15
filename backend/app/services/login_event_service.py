from sqlalchemy.orm import Session
from app.models.login_event import LoginEvent
from datetime import datetime, timezone

def mark_mfa_successful(db: Session, login_event_id: str) -> bool:
   
    try:
        login_event = db.query(LoginEvent).filter(LoginEvent.id == login_event_id).first()
        if not login_event:
            print(f"LoginEvent {login_event_id} not found")
            return False

        login_event.user_action = "approved"
        login_event.mfa_required = False
        login_event.device_last_seen_at = datetime.now(timezone.utc)
        db.commit()
        print(f"LoginEvent {login_event_id} marked as APPROVED")
        return True

    except Exception as e:
        db.rollback()
        print(f"Error updating LoginEvent: {e}")
        return False
