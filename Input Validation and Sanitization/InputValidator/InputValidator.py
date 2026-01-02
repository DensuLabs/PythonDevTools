import re
import html
import os
import ipaddress
from urllib.parse import urlparse

class InputValidator:
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format using a standard-compliant regex."""
        pattern = r"^[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$"
        return re.match(pattern, email) is not None

    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Validate IPv4 or IPv6 address using the standard library."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate URL scheme and structure."""
        try:
            result = urlparse(url)
            # Ensure it has a scheme (http/https) and a network location (domain)
            return all([result.scheme in ['http', 'https'], result.netloc])
        except Exception:
            return False

    @staticmethod
    def sanitize_html(text: str) -> str:
        """Escapes HTML entities to prevent basic XSS."""
        return html.escape(text, quote=True)

    @staticmethod
    def secure_filename(filename: str) -> str:
        """
        Prevents directory traversal by stripping paths and 
        blocking dangerous extensions.
        """
        # Force a flat filename (extracts 'file.txt' from '/etc/passwd/file.txt')
        base_name = os.path.basename(filename)
        
        # Remove any remaining path indicators
        base_name = base_name.replace("..", "").replace("/", "").replace("\\", "")
        
        dangerous_ext = {'.exe', '.bat', '.cmd', '.js', '.sh', '.php', '.py'}
        _, ext = os.path.splitext(base_name)
        
        if ext.lower() in dangerous_ext or not base_name:
            raise ValueError("Insecure or invalid filename provided.")
            
        return base_name