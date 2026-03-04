import threading
import time
import json
import logging

logger = logging.getLogger('forensic_cpa_ai')

def trigger_async_advisor_refresh(company_id: int, user_id: int, reason: str):
    """
    Marks company analysis as stale/queued, and spawns debounced background thread.
    Safely ignores repeated calls if a thread naturally assumes control.
    """
    from database import update_advisor_company_state
    
    # Fast atomic SQL UPDATE flipping state to `queued`
    update_advisor_company_state(
        company_id, 
        status='queued', 
        needs_refresh=1, 
        trigger_reason=reason
    )
    import os
    if os.environ.get('TESTING') == 'true':
        return
        
    # Fire and Forget Thread
    threading.Thread(target=_advisor_worker_loop, args=(company_id, user_id), daemon=True).start()

def _advisor_worker_loop(company_id: int, user_id: int):
    # 1. Debounce phase (3 seconds)
    # Collects burst inputs (e.g., 50 manual transaction PUTs arriving concurrently)
    time.sleep(3)
    
    from database import get_db
    conn = get_db()
    
    try:
        while True:
            # 2. Sequential Atomic Lock Acquisition
            cursor = conn.cursor()
            cursor.execute("BEGIN IMMEDIATE")
            
            cursor.execute("SELECT status, needs_refresh FROM advisor_company_state WHERE company_id = ?", (company_id,))
            row = cursor.fetchone()
            
            # If everything is already totally clean, stop thrashing CPU
            if not row or row['needs_refresh'] == 0:
                conn.commit()
                break
                
            # If another thread already acquired the write-lock post-debounce, exit!
            # It will detect `needs_refresh=1` independently and loop again organically.
            if row['status'] == 'running':
                conn.commit()
                break
                
            # Take logical engine lock natively in SQLite
            cursor.execute(
                "UPDATE advisor_company_state "
                "SET status = 'running', needs_refresh = 0, last_run_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP "
                "WHERE company_id = ?", (company_id,)
            )
            conn.commit()
            
            # 3. Execution (Must be completely outside DB transaction bounds)
            try:
                from advisor_service import get_advisor_aggregation_payload
                from advisor_orchestrator import run_advisor_orchestration
                from database import insert_advisor_findings
                import uuid
                
                # Retrieve raw dataset
                payload = get_advisor_aggregation_payload(user_id, company_id)
                payload['user_id'] = user_id
                payload['company_id'] = company_id
                
                # Deterministically compute insights
                results = run_advisor_orchestration(payload)
                
                # Persist canonical findings to the database
                analysis_run_id = str(uuid.uuid4())
                findings_to_insert = []
                for cat in ["fraud_red_flags", "key_findings", "document_intelligence", "internal_controls", "scenario_simulator"]:
                    for f in results.get(cat, []):
                        if "finding_id" in f:
                            findings_to_insert.append(f)
                
                insert_advisor_findings(company_id, analysis_run_id, findings_to_insert)
                
                from database import sync_remediation_tasks
                sync_remediation_tasks(company_id, findings_to_insert)
                
                results_json = json.dumps(results)
                
                # 4. Success Commit pushing rendered payload cache
                conn.execute(
                    "UPDATE advisor_company_state "
                    "SET status = 'completed', last_success_at = CURRENT_TIMESTAMP, last_result_json = ?, updated_at = CURRENT_TIMESTAMP "
                    "WHERE company_id = ?", (results_json, company_id)
                )
                conn.commit()
                
            except Exception as e:
                logger.error(f"Async Advisor Refresh failed for company {company_id}: {e}")
                # Release lock on algorithmic failure, preventing infinite DB trapping
                conn.execute(
                    "UPDATE advisor_company_state "
                    "SET status = 'failed', last_failure_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP "
                    "WHERE company_id = ?", (company_id,)
                )
                conn.commit()
                break # Exit loop so broken algorithms don't aggressively retry over identical raw data.
                
    except Exception as outer_e:
        logger.error(f"Fatal worker loop threading error bounded by SQLite limits: {outer_e}")
    finally:
        conn.close()
