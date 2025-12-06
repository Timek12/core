import logging
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from pwdlib import PasswordHash

from app.db.schema import Users, UserRole

logger = logging.getLogger(__name__)

# Password hashing - use the same pwdlib as auth_service
password_hash = PasswordHash.recommended()


def hash_password(password: str) -> str:
    """Hash a password using pwdlib"""
    return password_hash.hash(password)


def seed_initial_users(session: Session) -> bool:
    """Seed initial users into the database."""
    try:
        # Check if any users already exist
        existing_users_count = session.query(Users).count()
        
        if existing_users_count > 0:
            logger.info(f"Database already has {existing_users_count} users, skipping seeding")
            return True
        
        logger.info("No users found, seeding initial users...")
        
        # Define initial users
        initial_users = [
            {
                "email": "user1@gmail.com",
                "password": "User123@",
                "name": "Regular User",
                "role": UserRole.USER
            },
            {
                "email": "user2@example.com",
                "password": "User123@",
                "name": "User One",
                "role": UserRole.USER
            },
            {
                "email": "user3@example.com",
                "password": "User123@",
                "name": "User Two",
                "role": UserRole.USER
            },
            {
                "email": "user4@example.com",
                "password": "User123@",
                "name": "User Three",
                "role": UserRole.USER
            },
            {
                "email": "user5@example.com",
                "password": "User123@",
                "name": "User Four",
                "role": UserRole.USER
            },
            {
                "email": "admin@luna.com",
                "password": "Admin123@",
                "name": "Admin User",
                "role": UserRole.ADMIN
            },
            {
                "email": "admin2@luna.com",
                "password": "Admin123@",
                "name": "Admin Two",
                "role": UserRole.ADMIN
            }
        ]
        
        # Create users
        created_count = 0
        for user_data in initial_users:
            new_user = Users(
                email=user_data["email"],
                password_hash=hash_password(user_data["password"]),
                name=user_data["name"],
                role=user_data["role"],
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )
            
            session.add(new_user)
            created_count += 1
            
            role_name = user_data["role"].value.capitalize()
            logger.info(f"  Created {role_name}: {user_data['email']}")
        
        # Commit all users
        session.commit()
        
        logger.info(f"Successfully seeded {created_count} initial users")
        
        return True
        
    except Exception as e:
        logger.error(f"Error seeding users: {e}", exc_info=True)
        session.rollback()
        return False
