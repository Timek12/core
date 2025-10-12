import os
import uuid
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

import jwt
from pwdlib import PasswordHash
from sqlalchemy.orm import Session

from app.repositories.user_repository import UserRepository
from app.repositories.jwt_repository import JWTTokenRepository
from app.db.schema import Users, JWTRefreshTokens
from app.dto.user import UserCreate, UserResponse
from app.dto.token import InvalidTokenError, TokenPair, TokenPayload, TokenType

class AuthService:
    """Service for authentication and token management."""

    def __init__(self, db: Session):
        self.db = db
        self.user_repo = UserRepository(db)
        self.jwt_repo = JWTTokenRepository(db)
        self.password_hash = PasswordHash.recommended()

        # JWT configuration
        self.secret_key = os.getenv('JWT_SECRET_KEY')
        self.algorithm = "HS256"
        self.access_token_expire_minutes = int(os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES', '30'))
        self.refresh_token_expire_days = int(os.getenv('REFRESH_TOKEN_EXPIRE_DAYS', '7'))
    
    # Password operations
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        return self.password_hash.verify(plain_password, hashed_password)
    
    def hash_password(self, password: str) -> str:
        return self.password_hash.hash(password)
    
    # User operations
    def authenticate_user(self, email: str, password: str) -> Optional[Users]:
        user = self.user_repo.find_by_email(email)
        if not user:
            return None
        if not user.password_hash:
            return None
        if not self.verify_password(password, user.password_hash):
            return None
        return user
    
    def create_user(self, user_data: UserCreate) -> UserResponse:
        if self.user_repo.exists_by_email(user_data.email):
            raise ValueError(f"User with email {user_data.email} already exists")

        # Create user entity
        user = Users(
            email=user_data.email,
            name=user_data.name,
            avatar_url=user_data.avatar_url,
            provider_user_id=user_data.provider_user_id,
            auth_method=user_data.auth_method,
            provider=user_data.provider,
            password_hash=self.hash_password(user_data.password_hash) if user_data.password_hash else None,
            email_verified=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )

        saved_user = self.user_repo.save(user)
        return UserResponse.from_orm(saved_user)
    
    # Token operations
    def create_access_token(self, user_id: int, email: str) -> Tuple[str, datetime]:
        expires_delta = timedelta(minutes=self.access_token_expire_minutes)
        expire = datetime.now(timezone.utc) + expires_delta

        to_encode = {
            "sub": str(user_id),
            "email": email,
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "type": "access"
        }

        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt, expire
    
    def create_refresh_token(self, user_id: int, device_info: Optional[str] = None,
                              ip_address: Optional[str] = None) -> Tuple[str, JWTRefreshTokens]:
        # Generate unique JTI
        jti = uuid.uuid4()

        # Calculate expiration
        expires_delta = timedelta(days=self.refresh_token_expire_days)
        expire = datetime.now(timezone.utc) + expires_delta

        # Create token payload
        to_encode = {
            "sub": str(user_id),
            "jti": str(jti),
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "type": "refresh"
        }

        # Encode JWT
        refresh_token = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)

        # Hash token for storage
        token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()

        # Store in database
        db_token = JWTRefreshTokens(
            user_id=user_id,
            token_hash=token_hash,
            jti=jti,
            expires_at=expire,
            revoked=False,
            device_info=device_info,
            ip_address=ip_address,
            created_at=datetime.now(timezone.utc)
        )

        saved_token = self.jwt_repo.save(db_token)
        return refresh_token, saved_token
    
    def create_token_pair(self, user: Users, device_info: Optional[str] = None,
                        ip_address: Optional[str] = None) -> TokenPair:
        access_token, _ = self.create_access_token(user.user_id, user.email)
        refresh_token, _ = self.create_refresh_token(user.user_id, device_info, ip_address)

        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=self.access_token_expire_minutes * 60 # Convert to seconds
        )

    def verify_access_token(self, token: str) -> Optional[dict]:
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])

            # Check token type
            if payload.get("type") != TokenType.ACCESS:
                raise InvalidTokenError("Token is not an access token")
            
            user_id = payload.get("sub")
            if not user_id:
                raise InvalidTokenError("Token missing subject (user_id)")

            return TokenPayload(
                user_id=user_id,
                token_type=TokenType.ACCESS
            )
            
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError as e:
            raise InvalidTokenError(f"Invalid token: {str(e)}") from e
        except Exception as e:
            raise InvalidTokenError(f"Token verification failed: {str(e)}") from e
        
    def verify_refresh_token(self, token: str) -> Optional[JWTRefreshTokens]:
        try:
            # Decode JWT
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])

            # Check token type
            if payload.get("type") != "refresh":
                return None
            
            # Get JTI
            jti = payload.get("jti")
            if not jti:
                return None
            
            # Check database record
            db_token = self.jwt_repo.find_by_jti(uuid.UUID(jti))
            if not db_token:
                return None
            
            # Check if revoked
            if db_token.revoked:
                return None
            
            # Check expiration
            if db_token.expires_at < datetime.now(timezone.utc):
                return None
            
            # Hash provided token and compare with stored hash
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            if token_hash != db_token.token_hash:
                return None
            
            return db_token
        
        except jwt.ExpiredSignatureError:
            return None
        except jwt.jwt.InvalidTokenError:
            return None
        except ValueError:
            return None
        
    def refresh_access_token(self, refresh_token: str) -> Optional[str]:
        db_token = self.verify_refresh_token(refresh_token)
        if not db_token:
            return None
        
        # Get user
        user = self.user_repo.find_by_id(db_token.user_id)
        if not user:
            return None
        
        # Create new access token
        # TODO: Add creating new token pair
        access_token, _ = self.create_access_token(user.user_id, user.email)
        return access_token
    
    def revoke_token(self, token: str) -> bool:
        db_token = self.verify_refresh_token(token)
        if not db_token:
            return False
        
        return self.jwt_repo.revoke_token(db_token.jti)
    
    def revoke_all_user_tokens(self, user_id: int) -> int:
        return self.jwt_repo.revoke_all_user_tokens(user_id)
    
    def get_user_from_token(self, token: str) -> Optional[Users]:
        payload = self.verify_access_token(token)
        if not payload:
            return None
        
        user_id = payload.get("sub")
        if not user_id:
            return None
        
        return self.user_repo.find_by_id(int(user_id))
    

