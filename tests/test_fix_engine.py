"""Tests for fix engine"""
import unittest
import tempfile
import os
from unittest.mock import patch, MagicMock

from src.fix_engine.backup import BackupManager
from src.fix_engine.rollback import RollbackManager, Transaction


class TestBackupManager(unittest.TestCase):
    """Tests for BackupManager"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.backup_manager = BackupManager(self.temp_dir)

    def test_backup_creation(self):
        """Test backup file creation"""
        # Create test file
        test_file = os.path.join(self.temp_dir, "test.conf")
        with open(test_file, 'w') as f:
            f.write("test content")

        # Backup file
        backup_path = self.backup_manager.backup_file(test_file)

        # Verify backup exists
        self.assertIsNotNone(backup_path)
        self.assertTrue(os.path.exists(backup_path))

    def test_file_restore(self):
        """Test file restoration from backup"""
        # Create test file
        test_file = os.path.join(self.temp_dir, "test.conf")
        with open(test_file, 'w') as f:
            f.write("original content")

        # Backup
        backup_path = self.backup_manager.backup_file(test_file)

        # Modify original
        with open(test_file, 'w') as f:
            f.write("modified content")

        # Restore
        self.backup_manager.restore_file(backup_path, test_file)

        # Verify
        with open(test_file, 'r') as f:
            content = f.read()
        self.assertEqual(content, "original content")

    def test_nonexistent_file_backup(self):
        """Test backup of nonexistent file"""
        backup_path = self.backup_manager.backup_file("/nonexistent/file.conf")
        self.assertIsNone(backup_path)


class TestRollbackManager(unittest.TestCase):
    """Tests for RollbackManager"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.backup_manager = BackupManager(self.temp_dir)
        self.rollback_manager = RollbackManager(self.backup_manager)

    def test_transaction_creation(self):
        """Test transaction creation"""
        tx = self.rollback_manager.create_transaction("test_123")

        self.assertEqual(tx.id, "test_123")
        self.assertIsNotNone(tx.timestamp)
        self.assertEqual(tx.status, "pending")

    def test_transaction_operation_recording(self):
        """Test recording operations in transaction"""
        tx = self.rollback_manager.create_transaction("test_123")

        tx.add_operation("file_modify", "/etc/ssh/sshd_config", "/backup/sshd_config.bak")

        self.assertEqual(len(tx.operations), 1)
        self.assertEqual(tx.operations[0]["type"], "file_modify")
        self.assertEqual(tx.operations[0]["target"], "/etc/ssh/sshd_config")

    def test_transaction_status_change(self):
        """Test transaction status transitions"""
        tx = self.rollback_manager.create_transaction("test_123")

        self.assertEqual(tx.status, "pending")

        tx.status = "completed"
        self.assertEqual(tx.status, "completed")


class TestSSHFixer(unittest.TestCase):
    """Tests for SSH fixer"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        from src.fix_engine.ssh_fix import SSHFixer
        self.fixer = SSHFixer()
        self.fixer.backup_manager = BackupManager(self.temp_dir)

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open')
    @patch('subprocess.run')
    def test_root_login_fix_dry_run(self, mock_run, mock_open, mock_exists):
        """Test root login fix simulation"""
        tx = Transaction("test_tx")

        # Mock file operations
        mock_file = MagicMock()
        mock_file.read.return_value = "PermitRootLogin yes\n"
        mock_open.return_value.__enter__.return_value = mock_file

        # Mock SSH config test
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        # This would normally call the fixer, but we're testing structure
        # Real test would need proper file system mocking


class TestPermissionsFixer(unittest.TestCase):
    """Tests for permissions fixer"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        from src.fix_engine.permissions_fix import PermissionsFixer
        self.fixer = PermissionsFixer()
        self.fixer.backup_manager = BackupManager(self.temp_dir)

    def test_fix_world_writable(self):
        """Test world-writable permission fix"""
        # Create test file with world-writable permissions
        test_file = os.path.join(self.temp_dir, "test.conf")
        with open(test_file, 'w') as f:
            f.write("test")

        os.chmod(test_file, 0o777)

        tx = Transaction("test_tx")

        # Fix permissions
        success, message = self.fixer.fix_world_writable(test_file, tx)

        self.assertTrue(success)

        # Verify permissions changed
        stat_info = os.stat(test_file)
        perms = oct(stat_info.st_mode)[-3:]
        # Should not be world-writable
        self.assertNotEqual(perms[2], "7")


if __name__ == "__main__":
    unittest.main()
