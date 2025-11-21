"""Backup system for safe rollback"""
import os
import shutil
import logging
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


class BackupManager:
    """Manages file backups for rollback"""

    def __init__(self, backup_dir: str = "/var/lib/clay-sec-audit/backups"):
        self.backup_dir = backup_dir
        self._ensure_backup_dir()

    def _ensure_backup_dir(self):
        """Ensure backup directory exists"""
        os.makedirs(self.backup_dir, mode=0o700, exist_ok=True)

    def backup_file(self, filepath: str) -> Optional[str]:
        """Backup a file before modification"""
        if not os.path.exists(filepath):
            logger.error(f"File does not exist: {filepath}")
            return None

        try:
            # Create backup with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.basename(filepath)
            backup_path = os.path.join(self.backup_dir, f"{filename}.{timestamp}.bak")

            # Create subdirectories if needed
            os.makedirs(os.path.dirname(backup_path), mode=0o700, exist_ok=True)

            # Backup the file
            shutil.copy2(filepath, backup_path)
            logger.info(f"Backed up {filepath} to {backup_path}")
            return backup_path

        except Exception as e:
            logger.error(f"Failed to backup {filepath}: {e}")
            return None

    def restore_file(self, backup_path: str, original_path: str) -> bool:
        """Restore a file from backup"""
        try:
            if not os.path.exists(backup_path):
                logger.error(f"Backup file not found: {backup_path}")
                return False

            shutil.copy2(backup_path, original_path)
            logger.info(f"Restored {original_path} from {backup_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to restore {original_path}: {e}")
            return False

    def list_backups(self) -> dict:
        """List all backups"""
        backups = {}
        try:
            for root, dirs, files in os.walk(self.backup_dir):
                for file in files:
                    if file.endswith(".bak"):
                        filepath = os.path.join(root, file)
                        stat = os.stat(filepath)
                        backups[filepath] = {
                            "size": stat.st_size,
                            "timestamp": datetime.fromtimestamp(stat.st_mtime).isoformat()
                        }
        except Exception as e:
            logger.error(f"Failed to list backups: {e}")

        return backups
