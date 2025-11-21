"""Nginx hardening fixes"""
import logging
import os
import subprocess
from typing import Tuple
import re
from .backup import BackupManager
from .rollback import Transaction

logger = logging.getLogger(__name__)


class NginxFixer:
    """Fix Nginx security issues"""

    def __init__(self):
        self.backup_manager = BackupManager()
        self.nginx_config_paths = [
            "/etc/nginx/nginx.conf",
            "/etc/nginx/conf.d/default.conf",
            "/etc/nginx/sites-enabled/default"
        ]

    def _find_config_file(self) -> str:
        """Find the main Nginx config file"""
        for path in self.nginx_config_paths:
            if os.path.exists(path):
                return path
        return "/etc/nginx/nginx.conf"

    def _test_nginx_config(self) -> bool:
        """Test Nginx configuration"""
        result = subprocess.run(["nginx", "-t"], capture_output=True)
        return result.returncode == 0

    def _restart_nginx(self) -> bool:
        """Restart Nginx service"""
        result = subprocess.run(["systemctl", "restart", "nginx"], capture_output=True)
        return result.returncode == 0

    def fix_server_tokens(self, transaction: Transaction) -> Tuple[bool, str]:
        """Disable server tokens"""
        config_file = self._find_config_file()
        
        if not os.path.exists(config_file):
            return False, "Nginx config not found"

        backup_path = self.backup_manager.backup_file(config_file)
        if not backup_path:
            return False, "Failed to backup Nginx config"

        transaction.add_operation("file_modify", config_file, backup_path)

        try:
            with open(config_file, 'r') as f:
                content = f.read()

            if "server_tokens off" not in content:
                # Add after http { or in http block
                if "http {" in content:
                    content = content.replace("http {", "http {\n    server_tokens off;")
                else:
                    content += "\nserver_tokens off;\n"

            with open(config_file, 'w') as f:
                f.write(content)

            if not self._test_nginx_config():
                self.backup_manager.restore_file(backup_path, config_file)
                return False, "Nginx config test failed"

            self._restart_nginx()
            logger.info("Successfully disabled server tokens")
            return True, "server_tokens set to off"

        except Exception as e:
            logger.error(f"Failed to disable server tokens: {e}")
            self.backup_manager.restore_file(backup_path, config_file)
            return False, str(e)

    def fix_directory_listing(self, transaction: Transaction) -> Tuple[bool, str]:
        """Disable directory listing"""
        config_file = self._find_config_file()
        
        if not os.path.exists(config_file):
            return False, "Nginx config not found"

        backup_path = self.backup_manager.backup_file(config_file)
        if not backup_path:
            return False, "Failed to backup Nginx config"

        transaction.add_operation("file_modify", config_file, backup_path)

        try:
            with open(config_file, 'r') as f:
                content = f.read()

            # Replace autoindex on with autoindex off
            content = re.sub(r'autoindex\s+on;', 'autoindex off;', content, flags=re.IGNORECASE)

            with open(config_file, 'w') as f:
                f.write(content)

            if not self._test_nginx_config():
                self.backup_manager.restore_file(backup_path, config_file)
                return False, "Nginx config test failed"

            self._restart_nginx()
            logger.info("Successfully disabled directory listing")
            return True, "autoindex disabled"

        except Exception as e:
            logger.error(f"Failed to disable directory listing: {e}")
            self.backup_manager.restore_file(backup_path, config_file)
            return False, str(e)

    def add_security_headers(self, transaction: Transaction) -> Tuple[bool, str]:
        """Add security headers to Nginx"""
        config_file = self._find_config_file()
        
        if not os.path.exists(config_file):
            return False, "Nginx config not found"

        backup_path = self.backup_manager.backup_file(config_file)
        if not backup_path:
            return False, "Failed to backup Nginx config"

        transaction.add_operation("file_modify", config_file, backup_path)

        headers = [
            "add_header X-Content-Type-Options \"nosniff\" always;",
            "add_header X-Frame-Options \"DENY\" always;",
            "add_header X-XSS-Protection \"1; mode=block\" always;",
            "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
            "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"
        ]

        try:
            with open(config_file, 'r') as f:
                content = f.read()

            # Add headers in server block
            for header in headers:
                if header not in content:
                    # Find a good place to add it (after server_name)
                    content = re.sub(
                        r'(server_name\s+[^;]+;)',
                        r'\1\n        ' + header,
                        content
                    )

            with open(config_file, 'w') as f:
                f.write(content)

            if not self._test_nginx_config():
                self.backup_manager.restore_file(backup_path, config_file)
                return False, "Nginx config test failed"

            self._restart_nginx()
            logger.info("Successfully added security headers")
            return True, "Security headers added"

        except Exception as e:
            logger.error(f"Failed to add security headers: {e}")
            self.backup_manager.restore_file(backup_path, config_file)
            return False, str(e)

    def fix_ssl_tls(self, transaction: Transaction) -> Tuple[bool, str]:
        """Configure strong TLS settings"""
        config_file = self._find_config_file()
        
        if not os.path.exists(config_file):
            return False, "Nginx config not found"

        backup_path = self.backup_manager.backup_file(config_file)
        if not backup_path:
            return False, "Failed to backup Nginx config"

        transaction.add_operation("file_modify", config_file, backup_path)

        try:
            with open(config_file, 'r') as f:
                content = f.read()

            # Replace weak TLS configurations
            content = re.sub(
                r'ssl_protocols\s+[^;]+;',
                'ssl_protocols TLSv1.2 TLSv1.3;',
                content
            )

            if 'ssl_ciphers' not in content:
                content += "\nssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305';\n"

            with open(config_file, 'w') as f:
                f.write(content)

            if not self._test_nginx_config():
                self.backup_manager.restore_file(backup_path, config_file)
                return False, "Nginx config test failed"

            self._restart_nginx()
            logger.info("Successfully hardened TLS settings")
            return True, "TLS protocols updated to TLSv1.2+"

        except Exception as e:
            logger.error(f"Failed to harden TLS: {e}")
            self.backup_manager.restore_file(backup_path, config_file)
            return False, str(e)
