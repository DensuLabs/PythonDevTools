import os
import json
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

class SecureConfig:
    def __init__(self):
        self._config: Dict[str, Any] = {}
        self._sensitive_keys = {'password', 'token', 'key', 'secret', 'auth'}

    def load_env(self, key: str, default: Any = None, required: bool = False, cast_type: type = str):
        """Load and cast environment variables."""
        value = os.getenv(key)
        
        if value is None:
            if required:
                raise ValueError(f"CRITICAL: Missing required environment variable: {key}")
            value = default
        else:
            # Handle type casting (e.g., "True" -> True)
            try:
                if cast_type == bool:
                    value = str(value).lower() in ('true', '1', 't', 'y', 'yes')
                else:
                    value = cast_type(value)
            except (ValueError, TypeError):
                logger.error(f"Failed to cast {key} to {cast_type}")
                value = default

        self._config[key] = value
        return value

    def load_encrypted_file(self, filepath: str, decryption_callback=None):
        """Loads a file and passes it through a decryption provider."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Config file not found: {filepath}")

        try:
            with open(filepath, 'rb') as f:
                raw_data = f.read()
            
            # Decryption provider (e.g., AWS KMS, HashiCorp Vault, or Fernet)
            decrypted_data = decryption_callback(raw_data) if decryption_callback else raw_data
            
            new_config = json.loads(decrypted_data)
            self._config.update(new_config)
        except Exception as e:
            logger.critical(f"Security Failure: Could not load encrypted config: {e}")
            raise

    def get_safe_dump(self) -> Dict[str, Any]:
        """Returns the config with sensitive values redacted for logging."""
        masked = {}
        for k, v in self._config.items():
            if any(s in k.lower() for s in self._sensitive_keys):
                masked[k] = "[REDACTED]"
            else:
                masked[k] = v
        return masked

    def __getitem__(self, key):
        """Allow dict-style access: config['API_KEY']"""
        return self._config.get(key)