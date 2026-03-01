// shared/tableUtils.js

/**
 * Extracts and normalizes a value for sorting based on its declared type.
 * @param {any} val - The raw value from the row data
 * @param {string} type - 'text' | 'number' | 'currency' | 'date' | 'boolean'
 * @returns {any} A normalized value ready for standard < / > comparison
 */
function getSortableValue(val, type = 'text') {
    if (val === null || val === undefined) {
        // Return baseline minimums for null-safe sorting
        if (type === 'number' || type === 'currency') return -Infinity;
        if (type === 'date') return 0; // Epoch minimum
        if (type === 'boolean') return 0;
        return '';
    }

    switch (type) {
        case 'text':
            return String(val).trim().toLowerCase();

        case 'number':
            const num = Number(val);
            return isNaN(num) ? -Infinity : num;

        case 'currency':
            // Handles $1,000.00, -100, (100)
            const str = String(val).trim();
            let isNegative = str.startsWith('-') || (str.startsWith('(') && str.endsWith(')'));
            const cleaned = str.replace(/[$,()\-]/g, '');
            const cNum = Number(cleaned);
            if (isNaN(cNum)) return -Infinity;
            return isNegative ? -cNum : cNum;

        case 'date':
            // Assumes parsable date string or timestamp
            const d = new Date(val);
            return isNaN(d.getTime()) ? 0 : d.getTime();

        case 'boolean':
            // true=1, false=0
            if (typeof val === 'boolean') return val ? 1 : 0;
            return String(val).toLowerCase() === 'true' || val === '1' || val === 1 ? 1 : 0;

        default:
            return String(val).trim().toLowerCase();
    }
}

/**
 * Shared comparison function for sorting rows.
 * @param {Object} a - Row A
 * @param {Object} b - Row B
 * @param {string} sortBy - The property key to sort on
 * @param {string} sortType - The type of data (text, number, currency, date, boolean)
 * @param {string} sortDir - 'asc' or 'desc'
 */
function sortComparator(a, b, sortBy, sortType, sortDir = 'asc') {
    const valA = getSortableValue(a[sortBy], sortType);
    const valB = getSortableValue(b[sortBy], sortType);

    const modifier = sortDir === 'desc' ? -1 : 1;

    if (valA < valB) return -1 * modifier;
    if (valA > valB) return 1 * modifier;
    return 0;
}

/**
 * Helper to sort a full dataset non-destructively.
 */
function useTableSort(data, sortBy, sortType = 'text', sortDir = 'asc') {
    if (!sortBy || !Array.isArray(data)) return data;
    return [...data].sort((a, b) => sortComparator(a, b, sortBy, sortType, sortDir));
}

/**
 * Normalizes filter values for reliable matching
 */
function normalizeFilterValue(val, type) {
    if (val === null || val === undefined) return null;

    if (type === 'text' || type === 'select') {
        return String(val).trim().toLowerCase();
    }
    if (type === 'boolean') {
        const strVal = String(val).trim().toLowerCase();
        return strVal === '1' || strVal === 'true';
    }
    return val;
}

/**
 * Applies a set of filter configurations to an array of table rows.
 * @param {Array} data - The rows to filter
 * @param {Object} filterState - Current active filter values (e.g. { search: 'lunch', max_amount: 50 })
 * @param {Array} filterConfig - The rules defining how each state key behaves
 * 
 * Example filterConfig:
 * [
 *   { key: 'search', type: 'text', accessor: row => row.description },
 *   { key: 'category', type: 'select', accessor: row => row.category },
 *   { key: 'tags', type: 'multiselect', accessor: row => row.tags }, // array of strings
 *   { key: 'min_amount', type: 'numberRange', bound: 'min', accessor: row => row.amount },
 *   { key: 'date_from', type: 'dateRange', bound: 'min', accessor: row => row.date },
 *   { key: 'is_flagged', type: 'boolean', accessor: row => row.is_flagged }
 * ]
 */
function applyTableFilters(data, filterState, filterConfig) {
    if (!Array.isArray(data) || !filterConfig || !filterState) return data;

    // Quick escape if no active filters
    const activeFilters = filterConfig.filter(conf => {
        const val = filterState[conf.key];
        return val !== null && val !== undefined && val !== '';
    });

    if (activeFilters.length === 0) return data;

    return data.filter(row => {
        for (const conf of activeFilters) {
            const stateVal = filterState[conf.key];
            const rowValRaw = typeof conf.accessor === 'function' ? conf.accessor(row) : row[conf.key];

            // Null safety
            if ((rowValRaw === null || rowValRaw === undefined) && conf.type !== 'boolean') {
                return false; // Row fails this filter if value is null (unless boolean false/null logic handles it)
            }

            switch (conf.type) {
                case 'text':
                    const textSearch = normalizeFilterValue(stateVal, 'text');
                    const textVal = normalizeFilterValue(rowValRaw, 'text');
                    if (!textVal.includes(textSearch)) return false;
                    break;

                case 'select':
                    if (normalizeFilterValue(rowValRaw, 'select') !== normalizeFilterValue(stateVal, 'select')) {
                        return false;
                    }
                    break;

                case 'multiselect':
                    // Expects stateVal to be an array of selected options, or comma-separated string
                    const requiredSelections = Array.isArray(stateVal) ? stateVal : String(stateVal).split(',');
                    const rowVals = Array.isArray(rowValRaw) ? rowValRaw.map(v => normalizeFilterValue(v, 'select')) : [normalizeFilterValue(rowValRaw, 'select')];

                    // Inclusion check: row must have one of the required selections
                    const normalizedReq = requiredSelections.map(v => normalizeFilterValue(v, 'select'));
                    if (!normalizedReq.some(req => rowVals.includes(req))) {
                        return false;
                    }
                    break;

                case 'numberRange':
                    const maxAllowed = conf.bound === 'max';
                    const numFilter = Number(stateVal);
                    const rowNum = Number(rowValRaw);
                    if (isNaN(numFilter) || isNaN(rowNum)) return false;

                    if (maxAllowed && rowNum > numFilter) return false;
                    if (!maxAllowed && rowNum < numFilter) return false;
                    break;

                case 'dateRange':
                    const maxDate = conf.bound === 'max';
                    const dateFilter = new Date(stateVal).getTime();
                    const rowDate = new Date(rowValRaw).getTime();
                    if (isNaN(dateFilter) || isNaN(rowDate)) return false;

                    if (maxDate && rowDate > dateFilter) return false;
                    if (!maxDate && rowDate < dateFilter) return false;
                    break;

                case 'boolean':
                    const boolState = normalizeFilterValue(stateVal, 'boolean');
                    const boolRow = normalizeFilterValue(rowValRaw, 'boolean');
                    if (boolState && !boolRow) return false; // Only filter out if checked and row is false
                    break;
            }
        }
        return true; // Passed all filters
    });
}

function useTableFilters(data, filterState, filterConfig) {
    return applyTableFilters(data, filterState, filterConfig);
}

// Export for Node.js tests & attach to window for browser
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        getSortableValue,
        sortComparator,
        useTableSort,
        normalizeFilterValue,
        applyTableFilters,
        useTableFilters
    };
} else if (typeof window !== 'undefined') {
    Object.assign(window, {
        getSortableValue,
        sortComparator,
        useTableSort,
        normalizeFilterValue,
        applyTableFilters,
        useTableFilters
    });
}
