"""Database hardening fixes"""
import logging
import os
import subprocess
import re
from typing import Tuple
from .backup import BackupManager
from .rollback import Transaction

logger = logging.getLogger(__name__)


class DatabaseFixer:
    """Fix database security issues"""

    def __init__(self):
        self.backup_manager = BackupManager()

    def fix_mysql_bind_address(self, transaction: Transaction) -> Tuple[bool, str]:
        """Fix MySQL bind address to localhost"""
        config_file = "/etc/mysql/mysql.conf.d/mysqld.cnf"
        
        if not os.path.exists(config_file):
            return False, f"MySQL config not found: {config_file}"

        backup_path = self.backup_manager.backup_file(config_file)
        if not backup_path:
            return False, "Failed to backup MySQL config"

        transaction.add_operation("file_modify", config_file, backup_path)

        try:
            with open(config_file, 'r') as f:
                content = f.read()

            if "bind-address" in content:
                content = re.sub(
                    r'bind-address\s*=\s*\S+',
                    'bind-address = 127.0.0.1',
                    content
                )
            else:
                content += "\nbind-address = 127.0.0.1\n"

            with open(config_file, 'w') as f:
                f.write(content)

            # Restart MySQL
            subprocess.run(["systemctl", "restart", "mysql"], capture_output=True)

            logger.info("Successfully configured MySQL bind address")
            return True, "MySQL bind-address set to 127.0.0.1"

        except Exception as e:
            logger.error(f"Failed to fix MySQL bind address: {e}")
            self.backup_manager.restore_file(backup_path, config_file)
            return False, str(e)

    def fix_postgres_pg_hba(self, transaction: Transaction) -> Tuple[bool, str]:
        """Fix PostgreSQL pg_hba.conf for local access only"""
        config_file = "/etc/postgresql/13/main/pg_hba.conf"  # Adjust version as needed
        
        if not os.path.exists(config_file):
            # Try default location
            config_file = "/etc/postgresql/*/main/pg_hba.conf"
            stdout, _, _ = self.execute_command(f"find /etc/postgresql -name 'pg_hba.conf' -type f")
            if stdout.strip():
                config_file = stdout.strip().split('\n')[0]
            else:
                return False, "PostgreSQL pg_hba.conf not found"

        backup_path = self.backup_manager.backup_file(config_file)
        if not backup_path:
            return False, "Failed to backup pg_hba.conf"

        transaction.add_operation("file_modify", config_file, backup_path)

        try:
            with open(config_file, 'r') as f:
                lines = f.readlines()

            new_lines = []
            for line in lines:
                # Remove overly permissive rules
                if line.strip().startswith('#'):
                    new_lines.append(line)
                elif '0.0.0.0/0' in line or '::/0' in line:
                    # Replace with localhost only
                    new_lines.append(line.replace('0.0.0.0/0', '127.0.0.1/32').replace('::/0', '::1/128'))
                elif 'trust' in line:
                    # Replace trust with md5 or scram-sha-256
                    new_lines.append(line.replace('trust', 'scram-sha-256'))
                else:
                    new_lines.append(line)

            with open(config_file, 'w') as f:
                f.writelines(new_lines)

            # Reload PostgreSQL
            subprocess.run(["systemctl", "reload", "postgresql"], capture_output=True)

            logger.info("Successfully configured PostgreSQL pg_hba.conf")
            return True, "PostgreSQL authentication configured securely"

        except Exception as e:
            logger.error(f"Failed to fix pg_hba.conf: {e}")
            self.backup_manager.restore_file(backup_path, config_file)
            return False, str(e)

    def fix_mongodb_config(self, transaction: Transaction) -> Tuple[bool, str]:
        """Fix MongoDB bindIp configuration"""
        config_file = "/etc/mongod.conf"
        
        if not os.path.exists(config_file):
            return False, "MongoDB config not found"

        backup_path = self.backup_manager.backup_file(config_file)
        if not backup_path:
            return False, "Failed to backup MongoDB config"

        transaction.add_operation("file_modify", config_file, backup_path)

        try:
            with open(config_file, 'r') as f:
                content = f.read()

            # Fix bindIp
            if 'bindIp:' in content:
                content = re.sub(
                    r'bindIp:\s*[^\n]+',
                    'bindIp: 127.0.0.1',
                    content
                )
            else:
                content += "\nbindIp: 127.0.0.1\n"

            # Enable security
            if 'security:' not in content:
                content += "\nsecurity:\n  authorization: enabled\n"

            with open(config_file, 'w') as f:
                f.write(content)

            subprocess.run(["systemctl", "restart", "mongod"], capture_output=True)

            logger.info("Successfully configured MongoDB")
            return True, "MongoDB configured: bindIp=127.0.0.1, authorization=enabled"

        except Exception as e:
            logger.error(f"Failed to fix MongoDB config: {e}")
            self.backup_manager.restore_file(backup_path, config_file)
            return False, str(e)

    def fix_redis_config(self, transaction: Transaction) -> Tuple[bool, str]:
        """Fix Redis bind and password configuration"""
        config_file = "/etc/redis/redis.conf"
        
        if not os.path.exists(config_file):
            return False, "Redis config not found"

        backup_path = self.backup_manager.backup_file(config_file)
        if not backup_path:
            return False, "Failed to backup Redis config"

        transaction.add_operation("file_modify", config_file, backup_path)

        try:
            with open(config_file, 'r') as f:
                content = f.read()

            # Fix bind address
            if 'bind ' in content:
                content = re.sub(
                    r'bind\s+\S+',
                    'bind 127.0.0.1',
                    content
                )
            else:
                content += "\nbind 127.0.0.1\n"

            # Ensure requirepass is set
            if 'requirepass' not in content:
                import secrets
                password = secrets.token_hex(16)
                content += f"\nrequirepass {password}\n"
                logger.warning(f"Generated Redis password: {password}")
            else:
                content = re.sub(
                    r'# requirepass\s+.*',
                    'requirepass <strong_password>',
                    content
                )

            with open(config_file, 'w') as f:
                f.write(content)

            subprocess.run(["systemctl", "restart", "redis-server"], capture_output=True)

            logger.info("Successfully configured Redis")
            return True, "Redis configured: bind=127.0.0.1, requirepass enabled"

        except Exception as e:
            logger.error(f"Failed to fix Redis config: {e}")
            self.backup_manager.restore_file(backup_path, config_file)
            return False, str(e)

    @staticmethod
    def execute_command(cmd: str) -> Tuple[str, str, int]:
        """Execute command"""
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout, result.stderr, result.returncode
