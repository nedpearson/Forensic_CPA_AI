// tests/test_tableUtils.js
const test = require('node:test');
const assert = require('node:assert');
const {
    getSortableValue,
    sortComparator,
    useTableSort,
    normalizeFilterValue,
    applyTableFilters
} = require('../shared/tableUtils.js');

test('getSortableValue - text handling', (t) => {
    assert.strictEqual(getSortableValue(' LUNCH ', 'text'), 'lunch');
    assert.strictEqual(getSortableValue(null, 'text'), '');
});

test('getSortableValue - number handling', (t) => {
    assert.strictEqual(getSortableValue(50.5, 'number'), 50.5);
    assert.strictEqual(getSortableValue('50.5', 'number'), 50.5);
    assert.strictEqual(getSortableValue(null, 'number'), -Infinity);
});

test('getSortableValue - currency handling', (t) => {
    assert.strictEqual(getSortableValue('$1,234.56', 'currency'), 1234.56);
    assert.strictEqual(getSortableValue('($50.00)', 'currency'), -50.00);
    assert.strictEqual(getSortableValue('-100', 'currency'), -100);
    assert.strictEqual(getSortableValue(null, 'currency'), -Infinity);
});

test('getSortableValue - date handling', (t) => {
    assert.strictEqual(getSortableValue('2024-01-01', 'date'), 1704067200000); // UTC millis varies locally, just check it parses
    assert.ok(getSortableValue('2024-01-01', 'date') > getSortableValue('2023-12-31', 'date'));
    assert.strictEqual(getSortableValue(null, 'date'), 0);
    assert.strictEqual(getSortableValue('invalid-date', 'date'), 0);
});

test('getSortableValue - boolean handling', (t) => {
    assert.strictEqual(getSortableValue(true, 'boolean'), 1);
    assert.strictEqual(getSortableValue(false, 'boolean'), 0);
    assert.strictEqual(getSortableValue('1', 'boolean'), 1);
    assert.strictEqual(getSortableValue('0', 'boolean'), 0);
    assert.strictEqual(getSortableValue('true', 'boolean'), 1);
});

test('sortComparator & useTableSort', (t) => {
    const data = [
        { id: 1, val: '$10.00' },
        { id: 2, val: '($5.00)' },
        { id: 3, val: '$100.00' }
    ];

    const sortedAsc = useTableSort(data, 'val', 'currency', 'asc');
    assert.deepStrictEqual(sortedAsc.map(d => d.id), [2, 1, 3]);

    const sortedDesc = useTableSort(data, 'val', 'currency', 'desc');
    assert.deepStrictEqual(sortedDesc.map(d => d.id), [3, 1, 2]);

    // Non-mutating check
    assert.deepStrictEqual(data.map(d => d.id), [1, 2, 3]);
});

test('normalizeFilterValue', (t) => {
    assert.strictEqual(normalizeFilterValue(' TRUE ', 'boolean'), true);
    assert.strictEqual(normalizeFilterValue(' 1 ', 'boolean'), true);
    assert.strictEqual(normalizeFilterValue(' FALSE ', 'text'), 'false');
});

test('applyTableFilters - text search and exact select', (t) => {
    const data = [
        { desc: 'McDonalds', cat: 'Dining' },
        { desc: 'Burger King', cat: 'Dining' },
        { desc: 'Shell Gas', cat: 'Auto' }
    ];

    const res1 = applyTableFilters(data, { q: 'burger' }, [
        { key: 'q', type: 'text', accessor: r => r.desc }
    ]);
    assert.strictEqual(res1.length, 1);
    assert.strictEqual(res1[0].desc, 'Burger King');

    const res2 = applyTableFilters(data, { cat: 'Dining' }, [
        { key: 'cat', type: 'select', accessor: r => r.cat }
    ]);
    assert.strictEqual(res2.length, 2);
});

test('applyTableFilters - multiselect and ranges', (t) => {
    const data = [
        { amt: 10, cat: 'a' },
        { amt: 50, cat: 'b' },
        { amt: 100, cat: 'c' }
    ];

    const res1 = applyTableFilters(data, { filter_cat: ['a', 'c'] }, [
        { key: 'filter_cat', type: 'multiselect', accessor: r => r.cat }
    ]);
    assert.strictEqual(res1.length, 2);

    const res2 = applyTableFilters(data, { filter_cat: 'b,c', min_amt: 60 }, [
        { key: 'filter_cat', type: 'multiselect', accessor: r => r.cat },
        { key: 'min_amt', type: 'numberRange', bound: 'min', accessor: r => r.amt }
    ]);
    assert.strictEqual(res2.length, 1);
    assert.strictEqual(res2[0].amt, 100);
});
