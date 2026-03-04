import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app
from database import (
    get_db, update_advisor_company_state, get_advisor_company_state
)
from advisor_worker import trigger_async_advisor_refresh

class AdvisorRefreshTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.app = app.test_client()
        
        # We will manually interact with DB state for unit tests
        self.company_id_1 = 9991
        self.company_id_2 = 9992
        self.user_id = 9999
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM advisor_company_state WHERE company_id IN (?, ?)", (self.company_id_1, self.company_id_2))
        conn.commit()
        conn.close()

    def tearDown(self):
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM advisor_company_state WHERE company_id IN (?, ?)", (self.company_id_1, self.company_id_2))
        conn.commit()
        conn.close()

    def test_01_trigger_sets_queued_and_needs_refresh(self):
        """Verify that initially triggering an upload flags the DB state safely."""
        trigger_async_advisor_refresh(self.company_id_1, self.user_id, "Test Upload")
        
        state = get_advisor_company_state(self.company_id_1)
        self.assertIsNotNone(state)
        self.assertEqual(state['status'], 'queued')
        self.assertEqual(state['needs_refresh'], 1)
        self.assertEqual(state['trigger_reason'], "Test Upload")
        
        # Verify isolation
        state2 = get_advisor_company_state(self.company_id_2)
        self.assertIsNone(state2.get('status'))

    def test_02_running_status_is_protected_during_bursts(self):
        """Verify that if the thread is currently executing ('running'), new bursts do not overwrite the status lock."""
        # 1. Simulate worker holding the lock
        update_advisor_company_state(self.company_id_1, status="running", needs_refresh=0)
        
        # 2. Simulate User uploading a 2nd document while thread is busy
        # update_advisor_company_state uses CASE WHEN status = 'running' THEN 'running' ELSE 'queued' END
        update_advisor_company_state(self.company_id_1, status="queued", needs_refresh=1, trigger_reason="Burst Upload")
        
        state = get_advisor_company_state(self.company_id_1)
        self.assertEqual(state['status'], 'running', "Active thread execution status was unsafely overwritten!")
        self.assertEqual(state['needs_refresh'], 1, "Failed to capture staleness caused by the burst payload.")
        self.assertEqual(state['trigger_reason'], "Burst Upload")

    def test_03_failed_status_allow_retry(self):
        """Verify that a 'failed' sequence allows subsequent triggers to re-queue."""
        update_advisor_company_state(self.company_id_1, status="failed", needs_refresh=0)
        
        trigger_async_advisor_refresh(self.company_id_1, self.user_id, "Retry Request")
        
        state = get_advisor_company_state(self.company_id_1)
        self.assertEqual(state['status'], 'queued')
        self.assertEqual(state['needs_refresh'], 1)

if __name__ == '__main__':
    unittest.main()
