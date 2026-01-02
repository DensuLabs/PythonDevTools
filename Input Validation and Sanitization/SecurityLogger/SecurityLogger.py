import logging
import json
import traceback
from logging.handlers import RotatingFileHandler
from datetime import datetime

class SecurityLogger:
    def __init__(self, log_file="security.log", max_bytes=10_000_000, backup_count=5):
        self.logger = logging.getLogger("SecurityApp")
        self.logger.setLevel(logging.INFO)
        
        # Prevent duplicate logs if the logger is initialized multiple times
        if not self.logger.handlers:
            # Rotating File Handler: keeps logs under control
            handler = RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backup_count)
            
            # Use a formatter that makes logs easy to parse
            # Format: Timestamp | Level | JSON_Data
            formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def _emit(self, level, category, data):
        """Internal helper to structure data as JSON string."""
        log_entry = {
            "category": category,
            "timestamp": datetime.utcnow().isoformat(),
            **data
        }
        # Logging at the requested level
        if level == "INFO":
            self.logger.info(json.dumps(log_entry))
        elif level == "WARNING":
            self.logger.warning(json.dumps(log_entry))
        elif level == "ERROR":
            self.logger.error(json.dumps(log_entry))

    def log_security_event(self, event_type, details, severity="MEDIUM"):
        """Logs high-level security incidents."""
        self._emit("WARNING", "SECURITY_INCIDENT", {
            "event_type": event_type,
            "details": details,
            "severity": severity
        })

    def log_error(self, error, context="general_exception"):
        """Logs system errors with full traceback."""
        self._emit("ERROR", "SYSTEM_ERROR", {
            "context": context,
            "error_message": str(error),
            "traceback": traceback.format_exc().splitlines() # List format for better JSON readability
        })

    def log_access_attempt(self, user_id, resource, success, ip_address=None):
        """Logs authentication and authorization attempts."""
        self._emit("INFO", "ACCESS_CONTROL", {
            "user_id": user_id,
            "resource": resource,
            "status": "SUCCESS" if success else "FAILED",
            "ip_address": ip_address
        })