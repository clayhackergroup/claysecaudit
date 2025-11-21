"""Tests for scanner modules"""
import unittest
from unittest.mock import patch, MagicMock

from src.scanner.ports import PortScanner
from src.scanner.ssh import SSHAuditor
from src.scanner.filesystem import FilesystemAuditor


class TestPortScanner(unittest.TestCase):
    """Tests for PortScanner"""

    def setUp(self):
        self.scanner = PortScanner("localhost")

    def test_scanner_initialization(self):
        """Test scanner initialization"""
        self.assertEqual(self.scanner.hostname, "localhost")
        self.assertEqual(len(self.scanner.findings), 0)

    def test_risky_service_detection(self):
        """Test detection of risky services"""
        # Mock port output
        with patch.object(self.scanner, 'execute_local_command') as mock_exec:
            mock_exec.return_value = ("tcp  0 0 0.0.0.0:6379 0.0.0.0:* LISTEN", "", 0)
            
            results = self.scanner.scan()
            
            # Should detect Redis
            self.assertGreater(len(self.scanner.findings), 0)
            finding = self.scanner.findings[0]
            self.assertEqual(finding.severity, "critical")
            self.assertIn("Redis", finding.title)


class TestSSHAuditor(unittest.TestCase):
    """Tests for SSHAuditor"""

    def setUp(self):
        self.auditor = SSHAuditor("localhost")

    def test_ssh_config_parsing(self):
        """Test SSH config parsing"""
        config_content = """
        PermitRootLogin yes
        PasswordAuthentication yes
        X11Forwarding yes
        """
        
        self.auditor.config_content = config_content
        
        # Check root login
        root_login = self.auditor._get_config_value("PermitRootLogin")
        self.assertEqual(root_login, "yes")

    def test_root_login_detection(self):
        """Test detection of root login enabled"""
        config_content = "PermitRootLogin yes"
        self.auditor.config_content = config_content
        
        self.auditor._check_root_login()
        
        self.assertEqual(len(self.auditor.findings), 1)
        self.assertEqual(self.auditor.findings[0].severity, "critical")

    def test_password_auth_detection(self):
        """Test detection of password auth enabled"""
        config_content = "PasswordAuthentication yes"
        self.auditor.config_content = config_content
        
        self.auditor._check_password_auth()
        
        self.assertEqual(len(self.auditor.findings), 1)
        self.assertEqual(self.auditor.findings[0].severity, "high")

    def test_empty_password_detection(self):
        """Test detection of empty password support"""
        config_content = "PermitEmptyPasswords yes"
        self.auditor.config_content = config_content
        
        self.auditor._check_permit_empty_passwords()
        
        self.assertEqual(len(self.auditor.findings), 1)
        self.assertEqual(self.auditor.findings[0].severity, "critical")


class TestFilesystemAuditor(unittest.TestCase):
    """Tests for FilesystemAuditor"""

    def setUp(self):
        self.auditor = FilesystemAuditor("localhost")

    def test_world_writable_detection(self):
        """Test detection of world-writable files"""
        with patch.object(self.auditor, 'execute_local_command') as mock_exec:
            mock_exec.return_value = ("/etc/passwd\n/etc/shadow", "", 0)
            
            self.auditor._check_world_writable()
            
            self.assertGreater(len(self.auditor.findings), 0)

    def test_private_key_permission_check(self):
        """Test private key permission checking"""
        with patch('os.path.exists', return_value=True):
            with patch.object(self.auditor, 'execute_local_command') as mock_exec:
                # Simulate weak permissions
                mock_exec.side_effect = [
                    ("/root/.ssh/id_rsa", "", 0),  # find output
                    ("644", "", 0)  # stat output showing weak perms
                ]
                
                self.auditor._check_private_keys()
                
                # Should detect weak permissions
                self.assertGreater(len(self.auditor.findings), 0)


class TestScannerScoring(unittest.TestCase):
    """Tests for security scoring"""

    def test_overall_score_calculation(self):
        """Test overall score calculation"""
        from src.scanner.utils import Finding
        
        auditor = SSHAuditor()
        
        # Add findings
        auditor.add_finding(Finding(
            id="test1",
            category="SSH",
            severity="critical",
            title="Critical Issue",
            description="Test",
            affected_resource="Test",
            remediation="Test"
        ))
        
        score = auditor.get_overall_score()
        
        # Score should be less than 100
        self.assertLess(score, 100)
        self.assertGreater(score, 0)

    def test_severity_score_distribution(self):
        """Test severity score distribution"""
        from src.scanner.utils import Finding
        
        auditor = SSHAuditor()
        
        auditor.add_finding(Finding(
            id="critical1",
            category="SSH",
            severity="critical",
            title="Test",
            description="Test",
            affected_resource="Test",
            remediation="Test"
        ))
        
        auditor.add_finding(Finding(
            id="high1",
            category="SSH",
            severity="high",
            title="Test",
            description="Test",
            affected_resource="Test",
            remediation="Test"
        ))
        
        severity_score = auditor.calculate_severity_score()
        
        self.assertEqual(severity_score["critical"], 1)
        self.assertEqual(severity_score["high"], 1)


if __name__ == "__main__":
    unittest.main()
