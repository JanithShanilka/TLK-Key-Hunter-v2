"""Check campaign accounting and storage decisions without running a browser."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('campaign', Path(__file__).resolve().parents[1] / 'lab/offline_memory/run_campaign.py')
campaign = importlib.util.module_from_spec(spec)
spec.loader.exec_module(campaign)


class CampaignTests(unittest.TestCase):
    def test_failed_attempts_remain_in_denominator(self):
        result = campaign.aggregate([{'complete_offline_recovery': True}, {'status': 'failed'}, {'complete_offline_recovery': False}])
        self.assertEqual(result['attempted'], 3)
        self.assertEqual(result['successful'], 1)
        self.assertEqual(result['observed_success_fraction'], 1 / 3)
        self.assertIsNone(campaign.aggregate([])['observed_success_fraction'])

    def test_storage_requires_both_headroom_and_free_reserve(self):
        self.assertTrue(campaign.storage_ok(2, 30, 8, 20, 1))
        self.assertFalse(campaign.storage_ok(8, 30, 8, 20, 1))
        self.assertFalse(campaign.storage_ok(2, 19, 8, 20, 1))

    def test_atomic_result_and_failed_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            campaign.save(root / 'result.json', {'status': 'failed'})
            self.assertFalse((root / 'result.json.tmp').exists())
            with self.assertRaisesRegex(RuntimeError, 'stage_exit_7'):
                campaign.run_stage(['/bin/sh', '-c', 'exit 7'], root / 'stage.log', 10, lambda: True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
