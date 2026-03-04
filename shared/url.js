// shared/url.js

/**
 * Serialize a FilterSchema object into a stable query string.
 * @param {Object} filters 
 * @returns {string} url encoded query string
 */
function serializeFilters(filters) {
    if (!filters) return '';

    // Sort keys alphabetically for stable serialization ordering
    const keys = Object.keys(filters).sort();
    const params = new URLSearchParams();

    for (const k of keys) {
        const val = filters[k];
        if (val !== null && val !== undefined && val !== '') {
            params.append(k, String(val));
        }
    }
    return params.toString();
}

/**
 * Hydrate a query string into a FilterSchema object.
 * Ignores unknown keys to maintain backward compatibility.
 * @param {string} queryString (e.g., "?category=Dining&min_amount=10")
 * @returns {Object} FilterSchema
 */
function hydrateFilters(queryString) {
    const params = new URLSearchParams(queryString);
    const filters = {};

    // Known schema keys (for safety, ignoring malicious or unknown keys)
    const allowedKeys = [
        'search', 'category', 'cardholder', 'card_last_four', 'trans_type', 'date_from', 'date_to',
        'min_amount', 'max_amount', 'flags', 'view_mode', 'date_preset',
        'is_transfer', 'is_personal', 'is_business', 'is_flagged', 'account_id', 'payment_method'
    ];

    for (const [key, val] of params.entries()) {
        if (allowedKeys.includes(key)) {
            filters[key] = val;
        }
    }
    return filters;
}

// Export for Node.js tests & attach to window for browser
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { serializeFilters, hydrateFilters };
} else if (typeof window !== 'undefined') {
    window.serializeFilters = serializeFilters;
    window.hydrateFilters = hydrateFilters;
}
