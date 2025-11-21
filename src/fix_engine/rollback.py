"""Rollback system for safe recovery"""
import json
import os
import logging
from datetime import datetime
from typing import Dict, List, Optional
from .backup import BackupManager

logger = logging.getLogger(__name__)


class Transaction:
    """Represents a fix transaction that can be rolled back"""

    def __init__(self, transaction_id: str):
        self.id = transaction_id
        self.timestamp = datetime.now().isoformat()
        self.operations: List[Dict] = []
        self.status = "pending"  # pending, completed, rolled_back
        self.log_file = f"/var/lib/clay-sec-audit/transactions/{transaction_id}.json"

    def add_operation(self, operation_type: str, target: str, backup_path: Optional[str] = None):
        """Record an operation in the transaction"""
        self.operations.append({
            "type": operation_type,
            "target": target,
            "backup_path": backup_path,
            "timestamp": datetime.now().isoformat()
        })

    def save(self):
        """Save transaction to disk"""
        try:
            os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
            with open(self.log_file, 'w') as f:
                json.dump({
                    "id": self.id,
                    "timestamp": self.timestamp,
                    "status": self.status,
                    "operations": self.operations
                }, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save transaction: {e}")

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "status": self.status,
            "operations": self.operations
        }


class RollbackManager:
    """Manages rollback operations"""

    def __init__(self, backup_manager: Optional[BackupManager] = None):
        self.backup_manager = backup_manager or BackupManager()
        self.transactions: Dict[str, Transaction] = {}

    def create_transaction(self, transaction_id: str) -> Transaction:
        """Create a new transaction"""
        transaction = Transaction(transaction_id)
        self.transactions[transaction_id] = transaction
        return transaction

    def rollback_transaction(self, transaction_id: str) -> bool:
        """Rollback all operations in a transaction"""
        if transaction_id not in self.transactions:
            logger.error(f"Transaction not found: {transaction_id}")
            return False

        transaction = self.transactions[transaction_id]
        success = True

        # Rollback operations in reverse order
        for operation in reversed(transaction.operations):
            if operation["type"] == "file_modify" and operation.get("backup_path"):
                if not self.backup_manager.restore_file(operation["backup_path"], operation["target"]):
                    success = False
                    logger.error(f"Failed to restore {operation['target']}")
            elif operation["type"] == "file_delete":
                # Restore deleted files from backup
                if operation.get("backup_path"):
                    if not self.backup_manager.restore_file(operation["backup_path"], operation["target"]):
                        success = False

        if success:
            transaction.status = "rolled_back"
            transaction.save()
            logger.info(f"Successfully rolled back transaction {transaction_id}")
        else:
            logger.error(f"Partial rollback of transaction {transaction_id}")

        return success

    def commit_transaction(self, transaction_id: str) -> bool:
        """Mark transaction as completed"""
        if transaction_id not in self.transactions:
            logger.error(f"Transaction not found: {transaction_id}")
            return False

        transaction = self.transactions[transaction_id]
        transaction.status = "completed"
        transaction.save()
        return True

    def get_transaction(self, transaction_id: str) -> Optional[Transaction]:
        """Get transaction by ID"""
        return self.transactions.get(transaction_id)

    def get_transaction_history(self) -> List[Dict]:
        """Get all transaction history"""
        return [t.to_dict() for t in self.transactions.values()]
