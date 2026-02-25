// tests/test_store.js
const test = require('node:test');
const assert = require('node:assert');
const { GlobalFilterStore } = require('../shared/store.js');
const { serializeFilters, hydrateFilters } = require('../shared/url.js');

test('GlobalFilterStore - initialize and update', (t) => {
    const store = new GlobalFilterStore();
    assert.deepStrictEqual(store.getState(), {});

    let lastState = null;
    const unsub = store.subscribe((state) => { lastState = state; });

    store.update({ view_mode: 'business', is_flagged: '1' });
    assert.deepStrictEqual(store.getState(), { view_mode: 'business', is_flagged: '1' });
    assert.deepStrictEqual(lastState, { view_mode: 'business', is_flagged: '1' });

    // Update with null deletes key
    store.update({ is_flagged: null });
    assert.deepStrictEqual(store.getState(), { view_mode: 'business' });

    unsub();
});

test('GlobalFilterStore - clear preserves view_mode', (t) => {
    const store = new GlobalFilterStore({ view_mode: 'personal', search: 'hello' });
    store.clear();
    assert.deepStrictEqual(store.getState(), { view_mode: 'personal' });
});

test('GlobalFilterStore - replace', (t) => {
    const store = new GlobalFilterStore({ search: 'old' });
    store.replace({ category: 'Dining', date_preset: '30' });
    assert.deepStrictEqual(store.getState(), { category: 'Dining', date_preset: '30' });
});

test('serializeFilters - stable ordering and exclude empties', (t) => {
    const filters = {
        z_index: '1',
        category: 'Dining',
        empty_str: '',
        nulled: null,
        undefined_val: undefined,
        account_id: '123'
    };
    const result = serializeFilters(filters);
    // Keys account_id, category, z_index (alphabetical sorting expected)
    assert.strictEqual(result, 'account_id=123&category=Dining&z_index=1');
});

test('hydrateFilters - filters out unknown keys', (t) => {
    const qs = '?search=lunch&unknown_field=hacker&is_personal=1';
    const result = hydrateFilters(qs);
    assert.deepStrictEqual(result, { search: 'lunch', is_personal: '1' });
});

test('hydrateFilters - empty string input', (t) => {
    const result = hydrateFilters('');
    assert.deepStrictEqual(result, {});
});
