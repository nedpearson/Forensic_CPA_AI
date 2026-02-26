// tests/test_drilldown.js
const test = require('node:test');
const assert = require('node:assert');
const { DrilldownTarget } = require('../shared/types/index.js');
const { drilldownReducer, BreadcrumbStore, createDrilldownHandler } = require('../shared/drilldown.js');
const { serializeFilters, hydrateFilters } = require('../shared/url.js');

test('drilldownReducer - applies explicit filters and inherits view_mode', (t) => {
    const currentState = { view_mode: 'business', category: 'Dining', search: 'lunch' };
    const event = {
        target: DrilldownTarget.TRANSACTIONS,
        filters: { cardholder: 'Alice' }
    };

    const nextState = drilldownReducer(currentState, event);

    // Should drop category and search
    assert.strictEqual(nextState.category, undefined);
    assert.strictEqual(nextState.search, undefined);
    // Should inherit view_mode
    assert.strictEqual(nextState.view_mode, 'business');
    // Should have specific explicitly requested filters
    assert.strictEqual(nextState.cardholder, 'Alice');
});

test('drilldownReducer - overrides inherited view_mode if explicitly requested', (t) => {
    const currentState = { view_mode: 'business' };
    const event = {
        target: DrilldownTarget.TRANSACTIONS,
        filters: { view_mode: 'personal' }
    };
    const nextState = drilldownReducer(currentState, event);
    assert.strictEqual(nextState.view_mode, 'personal');
});

test('BreadcrumbStore - pushes, pops, and limits history', (t) => {
    const store = new BreadcrumbStore();
    store.push('Dashboard', 'dashboard', { view_mode: 'all' });
    store.push('Dining', DrilldownTarget.TRANSACTIONS, { category: 'Dining' });

    const history = store.getHistory();
    assert.strictEqual(history.length, 2);
    assert.strictEqual(history[0].label, 'Dashboard');

    // Prevent exactly same pushing logically
    store.push('Dining', DrilldownTarget.TRANSACTIONS, { category: 'Dining' });
    assert.strictEqual(store.getHistory().length, 2);

    const snapshot = store.pop(0);
    assert.deepStrictEqual(snapshot.filters, { view_mode: 'all' });
    assert.strictEqual(store.getHistory().length, 0); // popping drops what came after
});

test('createDrilldownHandler - logs and triggers navigation', (t) => {
    let triggeredNav = false;
    let loggedEvent = null;
    let bStore = new BreadcrumbStore();

    const handler = createDrilldownHandler({
        sourceTab: 'dashboard',
        widgetId: 'cat-chart',
        defaultTarget: DrilldownTarget.TRANSACTIONS,
        breadcrumbLabel: 'Dashboard > Categories',
        breadcrumbStore: bStore,
        getState: () => ({ view_mode: 'personal', search: 'ignored' }),
        onLogEvent: (record) => { loggedEvent = record; },
        onNavigate: (target, nextFilters) => {
            triggeredNav = true;
            assert.strictEqual(target, DrilldownTarget.TRANSACTIONS);
            assert.strictEqual(nextFilters.category, 'Dining');
        }
    });

    handler({ filters: { category: 'Dining' } });

    assert.ok(triggeredNav);
    assert.strictEqual(loggedEvent.widget_id, 'cat-chart');
    assert.strictEqual(loggedEvent.source_tab, 'dashboard');
    assert.strictEqual(bStore.getHistory().length, 1);
    assert.strictEqual(bStore.getHistory()[0].label, 'Dashboard > Categories');
});

test('drilldownReducer - Analysis Tab charts (Personal vs Business)', (t) => {
    // Simulating clicking on "Personal" slice of Personal vs Business chart for "Alice"
    const currentState = { view_mode: 'business', search: 'ignored' };
    const event = {
        target: DrilldownTarget.TRANSACTIONS,
        filters: { cardholder: 'Alice', is_personal: '1' }
    };
    const nextState = drilldownReducer(currentState, event);
    assert.strictEqual(nextState.cardholder, 'Alice');
    assert.strictEqual(nextState.is_personal, '1');
    assert.strictEqual(nextState.view_mode, 'business'); // Inherits correctly
    assert.strictEqual(nextState.search, undefined);
});

test('drilldownReducer - Analysis Tab charts (Timeline)', (t) => {
    // Simulating clicking a point on the Cardholder Timeline Comparison chart
    const currentState = { view_mode: 'all', category: 'travel' };
    const event = {
        target: DrilldownTarget.TRANSACTIONS,
        filters: { cardholder: 'Bob', date_from: '2024-01-01', date_to: '2024-01-31' }
    };
    const nextState = drilldownReducer(currentState, event);
    assert.strictEqual(nextState.category, undefined); // Dropped cross-category boundary
    assert.strictEqual(nextState.cardholder, 'Bob');
    assert.strictEqual(nextState.date_from, '2024-01-01');
    assert.strictEqual(nextState.date_to, '2024-01-31');
    assert.strictEqual(nextState.view_mode, 'all');
});

test('drilldownReducer - Categories Tab', (t) => {
    const currentState = { view_mode: 'all', search: 'venmo' };
    const event = {
        target: DrilldownTarget.TRANSACTIONS,
        filters: { category: 'Fraud' }
    };
    const nextState = drilldownReducer(currentState, event);
    assert.strictEqual(nextState.category, 'Fraud');
    assert.strictEqual(nextState.search, undefined);
});

test('serializeFilters - correctly serializes and ignores empty values', (t) => {
    const filters = {
        view_mode: 'business',
        category: 'Dining',
        search: '',
        min_amount: null,
        is_flagged: undefined,
        cardholder: 'Alice'
    };
    const qs = serializeFilters(filters);

    // Sort keys alphabetically is expected based on url.js implementation
    assert.strictEqual(qs, 'cardholder=Alice&category=Dining&view_mode=business');
});

test('hydrateFilters - correctly parses query string and ignores unknown keys', (t) => {
    const qs = '?category=Dining&view_mode=business&min_amount=100&malicious_script=true';
    const filters = hydrateFilters(qs);

    assert.strictEqual(filters.category, 'Dining');
    assert.strictEqual(filters.view_mode, 'business');
    assert.strictEqual(filters.min_amount, '100');
    assert.strictEqual(filters.malicious_script, undefined); // Should not be hydrated
});
