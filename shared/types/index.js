// shared/types/index.js

/**
 * FilterSchema defines the canonical shape of the GlobalFilterState.
 * @typedef {Object} FilterSchema
 * @property {string} [search] - Text search component
 * @property {string} [category] - Specified category name
 * @property {string} [cardholder] - Specified cardholder name
 * @property {string} [trans_type] - Transaction type (e.g. 'deposit')
 * @property {string} [date_from] - Start date (YYYY-MM-DD)
 * @property {string} [date_to] - End date (YYYY-MM-DD)
 * @property {string|number} [min_amount] - Minimum threshold
 * @property {string|number} [max_amount] - Maximum threshold
 * @property {string} [flags] - Flag type indicator
 * @property {string} [view_mode] - 'business', 'personal', or 'all'
 * @property {string} [date_preset] - Preset selector like '30' or 'ytd'
 * @property {string|number} [is_transfer] - Set to '1' if transfer
 * @property {string|number} [is_personal] - Set to '1' if personal
 * @property {string|number} [is_business] - Set to '1' if business
 * @property {string|number} [is_flagged] - Set to '1' if flagged
 * @property {string|number} [account_id] - Financial account ID
 * @property {string} [payment_method] - Method of payment
 */

/**
 * DrilldownTarget identifies what UI or data dimension a drilldown points to.
 * @enum {string}
 */
const DrilldownTarget = {
    TRANSACTIONS: 'TRANSACTIONS',
    MONTHLY_TREND: 'MONTHLY_TREND',
    CATEGORY: 'CATEGORY',
    CARDHOLDER: 'CARDHOLDER',
    ACCOUNT: 'ACCOUNT',
    DEPOSIT_AGING: 'DEPOSIT_AGING',
    RECIPIENT: 'RECIPIENT',
    MONEY_FLOW: 'MONEY_FLOW'
};

/**
 * DrilldownEvent payload describing the drilldown action
 * @typedef {Object} DrilldownEvent
 * @property {DrilldownTarget} target - Where the drilldown navigates to
 * @property {Partial<FilterSchema>} filters - Subset of filters explicitly applied for this destination
 * @property {Object} [metadata] - Optional UI metadata from origin component (e.g., chart slice index)
 */

/**
 * DTO for Executive Summary Tab Analytics
 * @typedef {Object} ExecutiveSummaryDTO
 * @property {number} total_analyzed
 * @property {string} date_range
 * @property {number} risk_score
 * @property {Array<{severity: string, title: string, detail: string}>} findings
 */

/**
 * DTO for Timeline Analytics Tab
 * @typedef {Object} TimelineDTO
 * @property {Array<{date: string, inflow: number, outflow: number, count: number, largest_trans: string}>} daily
 * @property {Object} insights - Extracted insights about balance velocity
 */

// Export for Node.js environments (like tests), or bind to window in browsers.
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { DrilldownTarget };
} else if (typeof window !== 'undefined') {
    window.DrilldownTarget = DrilldownTarget;
}
