"""Database exposure scanner"""
import logging
from typing import Dict
from .utils import ScannerBase, Finding

logger = logging.getLogger(__name__)


class DatabaseScanner(ScannerBase):
    """Scan for exposed databases"""

    DATABASES = {
        3306: {"name": "MySQL", "default_user": "root"},
        5432: {"name": "PostgreSQL", "default_user": "postgres"},
        27017: {"name": "MongoDB", "default_user": None},
        6379: {"name": "Redis", "default_user": None},
        5984: {"name": "CouchDB", "default_user": None},
    }

    def __init__(self, hostname: str = "localhost"):
        super().__init__(hostname)

    def scan(self) -> Dict[str, any]:
        """Scan for database exposure"""
        logger.info(f"Starting database scan on {self.hostname}")

        self._check_mysql()
        self._check_postgres()
        self._check_mongodb()
        self._check_redis()
        self._check_couchdb()

        findings = [f.to_dict() for f in self.findings]

        return {
            "findings": findings,
            "total_findings": len(self.findings),
            "severity_score": self.calculate_severity_score()
        }

    def _check_mysql(self):
        """Check MySQL configuration"""
        stdout, _, returncode = self.execute_local_command("which mysql mysqld 2>/dev/null | head -1")
        if returncode == 0:
            # Check MySQL config
            stdout, _, _ = self.execute_local_command("grep -r 'bind-address' /etc/mysql/ 2>/dev/null")
            if stdout.strip() and "127.0.0.1" not in stdout and "localhost" not in stdout:
                finding = Finding(
                    id="db_mysql_exposed",
                    category="Database Security",
                    severity="critical",
                    title="MySQL Bound to All Interfaces",
                    description="MySQL is listening on 0.0.0.0, exposing it to network access",
                    affected_resource="/etc/mysql/mysql.conf.d/mysqld.cnf",
                    remediation="Set 'bind-address = 127.0.0.1' to restrict access"
                )
                self.add_finding(finding)

            # Check for password validation
            stdout, _, _ = self.execute_local_command(
                "mysql -u root -e 'SELECT * FROM mysql.user WHERE User=\"\" OR authentication_string=\"\";' 2>/dev/null"
            )
            if "root" in stdout or stdout.strip():
                finding = Finding(
                    id="db_mysql_weak_auth",
                    category="Database Security",
                    severity="high",
                    title="MySQL Weak Authentication",
                    description="MySQL has empty passwords or anonymous users",
                    affected_resource="MySQL database",
                    remediation="Remove anonymous users and set strong passwords"
                )
                self.add_finding(finding)

    def _check_postgres(self):
        """Check PostgreSQL configuration"""
        stdout, _, returncode = self.execute_local_command("which postgres 2>/dev/null")
        if returncode == 0:
            # Check pg_hba.conf
            stdout, _, _ = self.execute_local_command("grep -E '^host|^local' /etc/postgresql/*/main/pg_hba.conf 2>/dev/null")
            if "0.0.0.0/0" in stdout:
                finding = Finding(
                    id="db_postgres_exposed",
                    category="Database Security",
                    severity="critical",
                    title="PostgreSQL Accepts All Connections",
                    description="PostgreSQL pg_hba.conf allows connections from 0.0.0.0/0",
                    affected_resource="/etc/postgresql/*/main/pg_hba.conf",
                    remediation="Restrict host-based access to specific IPs in pg_hba.conf"
                )
                self.add_finding(finding)

            # Check for weak authentication
            if "trust" in stdout:
                finding = Finding(
                    id="db_postgres_trust_auth",
                    category="Database Security",
                    severity="high",
                    title="PostgreSQL Trust Authentication",
                    description="PostgreSQL uses 'trust' authentication (no password required)",
                    affected_resource="/etc/postgresql/*/main/pg_hba.conf",
                    remediation="Change 'trust' to 'md5' or 'scram-sha-256' authentication"
                )
                self.add_finding(finding)

    def _check_mongodb(self):
        """Check MongoDB configuration"""
        stdout, _, returncode = self.execute_local_command("which mongod 2>/dev/null")
        if returncode == 0:
            # Check MongoDB binding
            stdout, _, _ = self.execute_local_command("grep 'bindIp' /etc/mongod.conf 2>/dev/null")
            if not stdout.strip() or "0.0.0.0" in stdout or "::" in stdout:
                finding = Finding(
                    id="db_mongodb_exposed",
                    category="Database Security",
                    severity="critical",
                    title="MongoDB Exposed to Network",
                    description="MongoDB is not bound to localhost",
                    affected_resource="/etc/mongod.conf",
                    remediation="Set 'bindIp: 127.0.0.1' in /etc/mongod.conf"
                )
                self.add_finding(finding)

            # Check for authentication
            stdout, _, _ = self.execute_local_command("grep 'security:' /etc/mongod.conf 2>/dev/null")
            if not stdout.strip():
                finding = Finding(
                    id="db_mongodb_no_auth",
                    category="Database Security",
                    severity="high",
                    title="MongoDB Authentication Disabled",
                    description="MongoDB is running without authentication enabled",
                    affected_resource="/etc/mongod.conf",
                    remediation="Enable security: in /etc/mongod.conf and set up authentication"
                )
                self.add_finding(finding)

    def _check_redis(self):
        """Check Redis configuration"""
        stdout, _, returncode = self.execute_local_command("which redis-server 2>/dev/null")
        if returncode == 0:
            # Check Redis binding
            stdout, _, _ = self.execute_local_command("grep 'bind' /etc/redis/redis.conf 2>/dev/null")
            if not stdout.strip() or "0.0.0.0" in stdout or ("::" in stdout and "127.0.0.1" not in stdout):
                finding = Finding(
                    id="db_redis_exposed",
                    category="Database Security",
                    severity="critical",
                    title="Redis Exposed to Network",
                    description="Redis is accessible from network without binding to localhost",
                    affected_resource="/etc/redis/redis.conf",
                    remediation="Set 'bind 127.0.0.1' in /etc/redis/redis.conf"
                )
                self.add_finding(finding)

            # Check for password
            stdout, _, _ = self.execute_local_command("grep '^requirepass' /etc/redis/redis.conf 2>/dev/null")
            if not stdout.strip():
                finding = Finding(
                    id="db_redis_no_password",
                    category="Database Security",
                    severity="high",
                    title="Redis Without Password",
                    description="Redis is running without authentication",
                    affected_resource="/etc/redis/redis.conf",
                    remediation="Set 'requirepass <strong_password>' in /etc/redis/redis.conf"
                )
                self.add_finding(finding)

    def _check_couchdb(self):
        """Check CouchDB configuration"""
        stdout, _, returncode = self.execute_local_command("which couchdb 2>/dev/null")
        if returncode == 0:
            # Check CouchDB binding
            stdout, _, _ = self.execute_local_command("grep 'bind_address' /etc/couchdb/local.ini 2>/dev/null")
            if not stdout.strip() or "0.0.0.0" in stdout:
                finding = Finding(
                    id="db_couchdb_exposed",
                    category="Database Security",
                    severity="critical",
                    title="CouchDB Exposed to Network",
                    description="CouchDB is not bound to localhost",
                    affected_resource="/etc/couchdb/local.ini",
                    remediation="Set 'bind_address = 127.0.0.1' in /etc/couchdb/local.ini"
                )
                self.add_finding(finding)
