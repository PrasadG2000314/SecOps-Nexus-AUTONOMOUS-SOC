"""
SecOps-Nexus Configuration & Zero-Trust Secret Management
Implements 12-Factor App security, strict environment isolation,
automatic cryptographic fallback key generation, and secret masking.
"""
import os
import secrets
from typing import Optional, Dict, Any

# Load environment variables from .env if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

class Settings:
    PROJECT_NAME: str = "SecOps-Nexus"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development").lower()
    DEBUG: bool = os.getenv("DEBUG", "false").lower() in ("true", "1", "yes")

    # API Server Settings
    HOST: str = os.getenv("HOST", "127.0.0.1")  # Default to localhost for secure binding
    PORT: int = int(os.getenv("PORT", "8000"))

    # Zero-Trust Cryptographic Secret for HMAC Verification
    # If not set in environment, generate an ephemeral cryptographically strong secret
    _env_hmac_secret = os.getenv("WEBHOOK_HMAC_SECRET")
    if _env_hmac_secret:
        WEBHOOK_HMAC_SECRET: str = _env_hmac_secret
    else:
        # Generate dynamic 256-bit cryptographically secure random secret
        WEBHOOK_HMAC_SECRET: str = secrets.token_hex(32)
        if ENVIRONMENT == "production":
            raise ValueError(
                "CRITICAL SECURITY MISCONFIGURATION: WEBHOOK_HMAC_SECRET must be explicitly "
                "set in production environment via Vault or .env file."
            )

    # AI Reasoning Engine Configuration
    GEMINI_API_KEY: Optional[str] = os.getenv("GEMINI_API_KEY", None)
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")

    # Privileged Access Management (PAM)
    VAULT_ADDR: str = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
    VAULT_TOKEN: Optional[str] = os.getenv("VAULT_TOKEN", None)
    PAM_SIMULATION_MODE: bool = os.getenv("PAM_SIMULATION_MODE", "true").lower() in ("true", "1", "yes")

    # Orchestrator & Bus Mode:
    STANDALONE_MODE: bool = os.getenv("STANDALONE_MODE", "true").lower() in ("true", "1", "yes")
    TEMPORAL_HOST: str = os.getenv("TEMPORAL_HOST", "localhost:7233")
    TEMPORAL_NAMESPACE: str = os.getenv("TEMPORAL_NAMESPACE", "default")
    KAFKA_BOOTSTRAP_SERVERS: str = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")

    # Risk & HITL Policies
    AUTO_CONTAINMENT_MAX_RISK: float = 30.0  # Contextual risk score threshold for autonomous fixes
    EPHEMERAL_TOKEN_TTL_SECONDS: int = 300   # 5-minute PAM access window

    @classmethod
    def get_masked_overview(cls) -> Dict[str, Any]:
        """Returns safe telemetry overview with all secrets securely masked."""
        def mask(val: Optional[str]) -> str:
            if not val:
                return "NOT_CONFIGURED"
            if len(val) <= 8:
                return "********"
            return f"{val[:4]}...{val[-4:]}"

        return {
            "environment": cls.ENVIRONMENT,
            "standalone_mode": cls.STANDALONE_MODE,
            "hmac_secret_status": "CONFIGURED_AND_ACTIVE" if cls.WEBHOOK_HMAC_SECRET else "MISSING",
            "gemini_api_key_configured": bool(cls.GEMINI_API_KEY),
            "gemini_api_key_masked": mask(cls.GEMINI_API_KEY),
            "vault_addr": cls.VAULT_ADDR,
            "vault_token_masked": mask(cls.VAULT_TOKEN),
            "pam_simulation_mode": cls.PAM_SIMULATION_MODE
        }

settings = Settings()
