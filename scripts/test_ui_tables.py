import os
import sys
import time
import requests
import subprocess
from playwright.sync_api import sync_playwright

PORT = 5008
BASE_URL = f"http://localhost:{PORT}"

def print_pass(msg):
    print(f"\033[92m[PASS]\033[0m {msg}")

def print_fail(msg):
    print(f"\033[91m[FAIL]\033[0m {msg}")
    sys.exit(1)

def start_server():
    env = os.environ.copy()
    env['FLASK_APP'] = 'app.py'
    env['FLASK_RUN_PORT'] = str(PORT)
    env['PORT'] = str(PORT)
    
    server = subprocess.Popen(
        [sys.executable, "-m", "flask", "run", "--port", str(PORT)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    
    for _ in range(20):
        try:
            time.sleep(1)
            response = requests.get(f"{BASE_URL}/")
            if response.status_code == 200:
                print_pass(f"Server is running on port {PORT}")
                return server
        except requests.ConnectionError:
            continue
            
    print_fail("Server failed to start.")
    server.terminate()
    return None

def test_js_utilities(page):
    print("--- Testing JS Sorting Utilities ---")
    
    # Text sort
    res = page.evaluate("getSortableValue(' Apple ', 'text')")
    assert res == 'apple', f"Failed text val: {res}"
    
    # Number sort
    res = page.evaluate("getSortableValue('-150.5', 'number')")
    assert res == -150.5, f"Failed num val: {res}"
    
    # Currency sort
    res = page.evaluate("getSortableValue('($1,500.25)', 'currency')")
    assert res == -1500.25, f"Failed currency val: {res}"
    res = page.evaluate("getSortableValue('$1,500.25', 'currency')")
    assert res == 1500.25, f"Failed currency val: {res}"
    
    # Date sort
    res = page.evaluate("getSortableValue('2025-01-01', 'date')")
    assert isinstance(res, (int, float)) and res > 0, f"Failed date val: {res}"
    
    # Boolean sort
    assert page.evaluate("getSortableValue(true, 'boolean')") == 1
    assert page.evaluate("getSortableValue('false', 'boolean')") == 0
    
    print_pass("getSortableValue works flawlessly.")

    print("--- Testing JS Sorting Logic ---")
    script = """
    () => {
        const data = [{val: 5}, {val: 10}, {val: -5}];
        const asc = useTableSort(data, 'val', 'number', 'asc').map(d => d.val);
        const desc = useTableSort(data, 'val', 'number', 'desc').map(d => d.val);
        return {asc, desc};
    }
    """
    res = page.evaluate(script)
    assert res['asc'] == [-5, 5, 10], f"Expected [-5, 5, 10], got {res['asc']}"
    assert res['desc'] == [10, 5, -5], f"Expected [10, 5, -5], got {res['desc']}"
    print_pass("useTableSort outputs correct order for numbers.")

    print("--- Testing JS Filtering Logic ---")
    script = """
    () => {
        const data = [
            {desc: 'Lunch at Subway'},
            {desc: 'Flight to NY'},
            {desc: 'Coffee'}
        ];
        const conf = [{key: 'search', type: 'text', accessor: r => r.desc}];
        const state = {search: 'lunch'};
        const filtered = applyTableFilters(data, state, conf);
        return filtered.map(d => d.desc);
    }
    """
    res = page.evaluate(script)
    assert res == ['Lunch at Subway'], f"Expected ['Lunch at Subway'], got {res}"
    print_pass("applyTableFilters text search overrides work safely.")

def test_dashboard_guards(page):
    print("--- Testing Dashboard Rendering Guards ---")
    script = """
    () => {
        // Mock empty stats object to verify no exceptions are thrown when rendering charts
        const mockStats = {
            monthly_trend: [],
            by_category: [],
            total_deposits: 0,
            total_withdrawals: 0,
            deposit_count: 0,
            withdrawal_count: 0,
            flagged_count: 0,
            by_cardholder: []
        };
        try {
            renderDashboardCharts(mockStats);
            return true;
        } catch (e) {
            return e.toString();
        }
    }
    """
    res = page.evaluate(script)
    assert res is True, f"Dashboard chart guards failed with Exception: {res}"
    
    has_empty_message = page.evaluate("document.getElementById('monthly-chart').parentNode.innerHTML.includes('No monthly data')")
    assert has_empty_message, "Safety string guard logic failed to insert empty message text for charts."
    print_pass("Dashboard rendering guards successfully defend against empty analytics arrays.")


def main():
    print("=== UI/JS STATE TESTS ===")
    server = start_server()
    if not server:
        sys.exit(1)
        
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            context = browser.new_context()
            page = context.new_page()
            
            # Note: Do not actually login to verify pure DOM scripts
            # Login first
            TEST_EMAIL = os.getenv('SUPER_ADMIN_EMAIL', 'nedpearson@gmail.com')
            TEST_PASSWORD = os.getenv('SUPER_ADMIN_PASSWORD', '1Pearson2')
            
            page.goto(BASE_URL)
            page.fill('#email', TEST_EMAIL)
            page.fill('#password', TEST_PASSWORD)
            page.click('button[type="submit"]')
            page.wait_for_timeout(3000)
            
            # Since the page is loaded, the tableUtils.js and Table.js files are already injected.
            # We can run our assertions directly.
            test_js_utilities(page)
            test_dashboard_guards(page)
            
    finally:
        server.terminate()
        
    print_pass("All UI components validated successfully!")

if __name__ == '__main__':
    main()
