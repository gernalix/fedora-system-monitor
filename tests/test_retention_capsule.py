import unittest

from fedora_system_monitor.capsules.database import Database, DEFAULT_METRIC_RETENTION_DAYS, StorageError
from fedora_system_monitor.capsules.database.retention import (
    RetentionStorageMixin, DEFAULT_METRIC_RETENTION_DAYS as CAPSULE_DEFAULTS,
)


class RetentionBoundaryTests(unittest.TestCase):
    def test_database_retains_public_methods_with_separate_policy(self):
        self.assertTrue(issubclass(Database, RetentionStorageMixin))
        self.assertIs(Database.apply_retention, RetentionStorageMixin.apply_retention)
        self.assertIs(Database._aggregate_metrics, RetentionStorageMixin._aggregate_metrics)
        self.assertIs(DEFAULT_METRIC_RETENTION_DAYS, CAPSULE_DEFAULTS)

    def test_retention_rejects_negative_values_without_database_mutation(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as root:
            with Database(Path(root) / 'test.sqlite') as db:
                with self.assertRaisesRegex(StorageError, 'negative'):
                    db.apply_retention(metric_days_by_cadence={60:-1})


if __name__=='__main__':
    unittest.main()
