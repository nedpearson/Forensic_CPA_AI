import os
import sys
import uuid

# Add the project root to the python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from database import (
    get_db, create_user, add_company_member, get_company_member_role, update_company_member_role, remove_company_member, 
    transfer_company_ownership, soft_delete_company, upsert_integration, 
    get_integrations
)

def setup_test_users():
    conn = get_db()
    conn.cursor()
    # Create two unique users
    u1_email = f"test_owner_{uuid.uuid4()}@example.com"
    u2_email = f"test_target_{uuid.uuid4()}@example.com"
    u3_email = f"test_other_{uuid.uuid4()}@example.com"
    
    u1 = create_user(u1_email, "pass123")
    u2 = create_user(u2_email, "pass123")
    u3 = create_user(u3_email, "pass123")
    return u1, u2, u3

def test_company_admin_flow():
    u1, u2, u3 = setup_test_users()
    conn = get_db()
    cursor = conn.cursor()
    
    # 1. Create a Company for u1
    cursor.execute("INSERT INTO companies (name, created_by, owner_user_id) VALUES (?, ?, ?)", ("Smoke Test Co", u1, u1))
    comp_id = cursor.lastrowid
    
    # Add u1 as owner
    cursor.execute("INSERT INTO company_memberships (user_id, company_id, role, is_default) VALUES (?, ?, 'owner', 1)", (u1, comp_id))
    conn.commit()
    
    # 2. Add Member (u2)
    assert add_company_member(comp_id, u2, 'operator')
    assert get_company_member_role(comp_id, u2) == 'operator'
    
    # 3. Update Member Role
    assert update_company_member_role(comp_id, u2, 'admin')
    assert get_company_member_role(comp_id, u2) == 'admin'
    
    # 4. Transfer Ownership to u2
    success, msg = transfer_company_ownership(comp_id, u1, u2)
    assert success, msg
    assert get_company_member_role(comp_id, u2) == 'owner'
    assert get_company_member_role(comp_id, u1) == 'admin'
    
    # 5. Remove u1
    success, msg = remove_company_member(comp_id, u1)
    assert success, msg
    assert get_company_member_role(comp_id, u1) is None
    
    # Attempt removing the only owner (u2)
    success, msg = remove_company_member(comp_id, u2)
    assert not success, "Should not be able to remove the only owner"
    
    # 6. Integrations Isolation Test
    # Create another company
    cursor.execute("INSERT INTO companies (name, created_by, owner_user_id) VALUES (?, ?, ?)", ("Other Co", u3, u3))
    comp2_id = cursor.lastrowid
    cursor.execute("INSERT INTO company_memberships (user_id, company_id, role, is_default) VALUES (?, ?, 'owner', 1)", (u3, comp2_id))
    conn.commit()
    
    # Add integration for comp 1
    upsert_integration(user_id=u2, provider="test_provider", company_id=comp_id)
    
    # Ensure it shows up for comp 1
    ints_c1 = get_integrations(u2, company_id=comp_id)
    assert len(ints_c1) == 1
    assert ints_c1[0]['provider'] == 'test_provider'
    
    # Does not show up for comp 2 even if u2 was a member (though they aren't)
    ints_c2 = get_integrations(u3, company_id=comp2_id)
    assert len(ints_c2) == 0
    
    # 7. Soft Delete
    assert soft_delete_company(comp_id)
    cursor.execute("SELECT status FROM companies WHERE id = ?", (comp_id,))
    assert cursor.fetchone()['status'] == 'deleted'
    
    conn.close()

if __name__ == "__main__":
    test_company_admin_flow()
    print("✅ Smoke test passed!")
