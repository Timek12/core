from typing import List
from fastapi import FastAPI, HTTPException
import uuid6
import uuid
from datetime import datetime, timedelta
from models.secret import Secret, SecretCreate, SecretUpdate

api = FastAPI()

@api.get('/health')
def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

now = datetime.now()

all_secrets: List[Secret] = [
    Secret(
        id=uuid6.uuid7(),
        name="db-password",
        description="Database connection password",
        key_id=uuid6.uuid7(),
        encrypted_value="gAAAAABlYXNkZmFrZQ==",
        version=1,
        created_at=now - timedelta(days=10),
        updated_at=now - timedelta(days=5),
    ),
    Secret(
        id=uuid6.uuid7(),
        name="api-token",
        description="Token for external API integration",
        key_id=uuid6.uuid7(),
        encrypted_value="bXlzdXBlcnNlY3JldA==",
        version=2,
        created_at=now - timedelta(days=20),
        updated_at=now - timedelta(days=2),
    ),
    Secret(
        id=uuid6.uuid7(),
        name="jwt-signing-key",
        description="Private key for JWT signing",
        key_id=uuid6.uuid7(),
        encrypted_value="U29tZUVuY3J5cHRlZEtleQ==",
        version=3,
        created_at=now - timedelta(days=30),
        updated_at=now - timedelta(days=1),
    ),
    Secret(
        id=uuid6.uuid7(),
        name="smtp-password",
        description="Password for SMTP email service",
        key_id=uuid6.uuid7(),
        encrypted_value="U01UUC1QYXNzZWQ=",
        version=1,
        created_at=now - timedelta(days=15),
        updated_at=now - timedelta(days=7),
    ),
    Secret(
        id=uuid6.uuid7(),
        name="payment-gateway-key",
        description="Secret key for payment gateway",
        key_id=uuid6.uuid7(),
        encrypted_value="UGF5bWVudC1HZXR3YXktU2VjcmV0",
        version=4,
        created_at=now - timedelta(days=60),
        updated_at=now - timedelta(hours=12),
    ),
]

@api.get('/secrets', response_model=List[Secret])
def get_secrets():
    return all_secrets

@api.post('/secrets', response_model=Secret)
def create_secret(secret: SecretCreate):
    new_secret = Secret(
        id=uuid6.uuid7(),
        name=secret.name,
        description=secret.description,
        key_id=uuid6.uuid7(),
        encrypted_value=secret.encrypted_value,
        version=secret.version,
        created_at=datetime.now(),
        updated_at=datetime.now(),
    )

    all_secrets.append(new_secret)

    return new_secret

@api.put('/secrets/{secret_id}', response_model=Secret)
def update_secret(secret_id: uuid.UUID, updated_secret: SecretUpdate):
    for secret in all_secrets:
        if secret.id == secret_id:
            if updated_secret.name is not None:
                secret.name = updated_secret.name
            if updated_secret.description is not None:
                secret.description = updated_secret.description
            if updated_secret.encrypted_value is not None:
                secret.encrypted_value = updated_secret.encrypted_value
            if updated_secret.version is not None:
                secret.version = updated_secret.version
            if updated_secret.updated_at is not None:
                secret.updated_at = updated_secret.updated_at
  
            return secret

    raise HTTPException(status_code=404, detail='Secret not found')    


@api.delete('/secrets/{secret_id}', response_model=Secret)
def delete_secret(secret_id: uuid.UUID):
    for index, secret in enumerate(all_secrets):
        if secret.id == secret_id:
            all_secrets.pop(index)

            return secret
    
    raise HTTPException(status_code=404, detail='Secret not found')    