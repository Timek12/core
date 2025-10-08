from typing import List, Optional
from sqlalchemy.orm import Session
from app.db.schema import Users


class UserRepository:
    """Repository for User entity data access operations."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def find_all(self) -> List[Users]:
        """Get all users."""
        return self.db.query(Users).all()
    
    def find_by_id(self, user_id: int) -> Optional[Users]:
        """Find user by ID."""
        return self.db.query(Users).filter(Users.user_id == user_id).first()
    
    def find_by_email(self, email: str) -> Optional[Users]:
        """Find user by email."""
        return self.db.query(Users).filter(Users.email == email).first()
    
    def find_by_provider_user_id(self, provider: str, provider_user_id: str) -> Optional[Users]:
        """Find user by provider and provider_user_id."""
        return self.db.query(Users).filter(
            Users.provider == provider,
            Users.provider_user_id == provider_user_id
        ).first()
    
    def find_by_auth_method(self, auth_method: str) -> List[Users]:
        """Find all users by authentication method."""
        return self.db.query(Users).filter(Users.auth_method == auth_method).all()
    
    def find_verified_users(self) -> List[Users]:
        """Find all verified users."""
        return self.db.query(Users).filter(Users.email_verified == True).all()
    
    def save(self, user: Users) -> Users:
        """Save a new user."""
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user
    
    def update(self, user: Users) -> Users:
        """Update existing user."""
        self.db.commit()
        self.db.refresh(user)
        return user
    
    def delete(self, user: Users) -> None:
        """Delete a user."""
        self.db.delete(user)
        self.db.commit()
    
    def exists_by_email(self, email: str) -> bool:
        """Check if user exists by email."""
        return self.db.query(Users).filter(Users.email == email).first() is not None
    
    def exists_by_provider(self, provider: str, provider_user_id: str) -> bool:
        """Check if user exists by provider credentials."""
        return self.db.query(Users).filter(
            Users.provider == provider,
            Users.provider_user_id == provider_user_id
        ).first() is not None