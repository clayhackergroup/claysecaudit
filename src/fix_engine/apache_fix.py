"""Apache hardening fixes"""
import logging
import os
import subprocess
import re
from typing import Tuple
from .backup import BackupManager
from .rollback import Transaction

logger = logging.getLogger(__name__)


class ApacheFixer:
    """Fix Apache security issues"""

    def __init__(self):
        self.backup_manager = BackupManager()
        self.apache_config_paths = [
            "/etc/apache2/apache2.conf",
            "/etc/apache2/conf-enabled/security.conf",
            "/etc/httpd/conf/httpd.conf"
        ]

    def _find_config_file(self) -> str:
        """Find the main Apache config file"""
        for path in self.apache_config_paths:
            if os.path.exists(path):
                return path
        return "/etc/apache2/apache2.conf"

    def _test_apache_config(self) -> bool:
        """Test Apache configuration"""
        result = subprocess.run(["apachectl", "configtest"], capture_output=True)
        return result.returncode == 0

    def _restart_apache(self) -> bool:
        """Restart Apache service"""
        result = subprocess.run(["systemctl", "restart", "apache2"], capture_output=True)
        if result.returncode != 0:
            result = subprocess.run(["systemctl", "restart", "httpd"], capture_output=True)
        return result.returncode == 0

    def fix_server_tokens(self, transaction: Transaction) -> Tuple[bool, str]:
        """Configure ServerTokens and ServerSignature"""
        config_file = self._find_config_file()
        
        if not os.path.exists(config_file):
            return False, "Apache config not found"

        backup_path = self.backup_manager.backup_file(config_file)
        if not backup_path:
            return False, "Failed to backup Apache config"

        transaction.add_operation("file_modify", config_file, backup_path)

        try:
            with open(config_file, 'r') as f:
                content = f.read()

            # Replace ServerTokens
            if "ServerTokens" in content:
                content = re.sub(r'ServerTokens\s+\S+', 'ServerTokens Prod', content, flags=re.IGNORECASE)
            else:
                content += "\nServerTokens Prod\n"

            # Replace ServerSignature
            if "ServerSignature" in content:
                content = re.sub(r'ServerSignature\s+\S+', 'ServerSignature Off', content, flags=re.IGNORECASE)
            else:
                content += "ServerSignature Off\n"

            with open(config_file, 'w') as f:
                f.write(content)

            if not self._test_apache_config():
                self.backup_manager.restore_file(backup_path, config_file)
                return False, "Apache config test failed"

            self._restart_apache()
            logger.info("Successfully configured server tokens")
            return True, "ServerTokens set to Prod, ServerSignature set to Off"

        except Exception as e:
            logger.error(f"Failed to fix server tokens: {e}")
            self.backup_manager.restore_file(backup_path, config_file)
            return False, str(e)

    def fix_directory_listing(self, transaction: Transaction) -> Tuple[bool, str]:
        """Disable directory listing"""
        config_file = self._find_config_file()
        
        if not os.path.exists(config_file):
            return False, "Apache config not found"

        backup_path = self.backup_manager.backup_file(config_file)
        if not backup_path:
            return False, "Failed to backup Apache config"

        transaction.add_operation("file_modify", config_file, backup_path)

        try:
            with open(config_file, 'r') as f:
                content = f.read()

            # Remove Indexes from Options
            content = re.sub(r'Options\s+([^;\n]*)\bIndexes\b([^\n;]*)', r'Options \1\2', content, flags=re.IGNORECASE)

            # Add -Indexes if not present
            if "Options -Indexes" not in content:
                content = re.sub(r'<Directory\s+/', '<Directory />\n    Options -Indexes', content, count=1)

            with open(config_file, 'w') as f:
                f.write(content)

            if not self._test_apache_config():
                self.backup_manager.restore_file(backup_path, config_file)
                return False, "Apache config test failed"

            self._restart_apache()
            logger.info("Successfully disabled directory listing")
            return True, "Directory indexing disabled"

        except Exception as e:
            logger.error(f"Failed to disable directory listing: {e}")
            self.backup_manager.restore_file(backup_path, config_file)
            return False, str(e)

    def add_security_headers(self, transaction: Transaction) -> Tuple[bool, str]:
        """Add security headers to Apache"""
        config_file = self._find_config_file()
        
        if not os.path.exists(config_file):
            return False, "Apache config not found"

        backup_path = self.backup_manager.backup_file(config_file)
        if not backup_path:
            return False, "Failed to backup Apache config"

        transaction.add_operation("file_modify", config_file, backup_path)

        headers = [
            'Header always set X-Content-Type-Options "nosniff"',
            'Header always set X-Frame-Options "DENY"',
            'Header always set X-XSS-Protection "1; mode=block"',
            'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"'
        ]

        try:
            with open(config_file, 'r') as f:
                content = f.read()

            for header in headers:
                if header not in content:
                    content += f"\n{header}\n"

            with open(config_file, 'w') as f:
                f.write(content)

            if not self._test_apache_config():
                self.backup_manager.restore_file(backup_path, config_file)
                return False, "Apache config test failed"

            self._restart_apache()
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
            return False, "Apache config not found"

        backup_path = self.backup_manager.backup_file(config_file)
        if not backup_path:
            return False, "Failed to backup Apache config"

        transaction.add_operation("file_modify", config_file, backup_path)

        try:
            with open(config_file, 'r') as f:
                content = f.read()

            # Remove weak protocols
            content = re.sub(
                r'SSLProtocol\s+[^;\n]+',
                'SSLProtocol TLSv1.2 TLSv1.3',
                content,
                flags=re.IGNORECASE
            )

            if 'SSLCipherSuite' not in content:
                content += "\nSSLCipherSuite 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384'\n"

            with open(config_file, 'w') as f:
                f.write(content)

            if not self._test_apache_config():
                self.backup_manager.restore_file(backup_path, config_file)
                return False, "Apache config test failed"

            self._restart_apache()
            logger.info("Successfully hardened TLS settings")
            return True, "TLS protocols updated to TLSv1.2+"

        except Exception as e:
            logger.error(f"Failed to harden TLS: {e}")
            self.backup_manager.restore_file(backup_path, config_file)
            return False, str(e)
