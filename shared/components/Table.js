/**
 * A reusable table builder component that integrates sorting and filtering.
 * Requires tableUtils.js to be loaded beforehand.
 */

class DataTable {
    /**
     * @param {Object} options
     * @param {string} options.containerId - The ID of the container element
     * @param {Array<Object>} options.data - The raw un-sorted, un-filtered data
     * @param {Array<Object>} options.columns - Column configuration
     * @param {Object} [options.filterConfig] - Optional filter configuration map
     * @param {Function} options.renderRow - Function that returns the HTML string for a single row
     * @param {string} [options.emptyMessage] - Message to display when no data matches
     */
    constructor(options) {
        this.containerId = options.containerId;
        this.rawData = options.data || [];
        this.columns = options.columns || [];
        this.filterConfig = options.filterConfig || [];
        this.renderRow = options.renderRow;
        this.emptyMessage = options.emptyMessage || 'No data available.';

        // Register to global pool for inline event handlers
        window._tableInstances = window._tableInstances || {};
        window._tableInstances[this.containerId] = this;

        // State
        this.sortState = { key: null, dir: null, type: null };
        this.filterState = {}; // Local filter override, else defaults to global

        // Caches
        this._filteredData = [];
        this._sortedData = [];

        this.init();
    }

    init() {
        this.container = document.getElementById(this.containerId);
        if (!this.container) {
            console.error(`DataTable: Container #${this.containerId} not found.`);
            return;
        }
        // Event delegation removed in favor of direct binding after render to ensure stability
    }

    updateData(newData) {
        this.rawData = newData || [];
        this.applyFilters(); // Internally calls applySort and render
    }

    applyFilters(externalFilterState = null) {
        // If an external state is provided (e.g. from GlobalFilterStore), use it
        const filtersToApply = externalFilterState || this.filterState;

        if (typeof applyTableFilters === 'function') {
            this._filteredData = applyTableFilters(this.rawData, filtersToApply, this.filterConfig);
        } else {
            console.warn('DataTable: applyTableFilters not found. Skipping filtering.');
            this._filteredData = [...this.rawData];
        }

        this.applySort();
        this.render();
    }

    applySort() {
        if (!this.sortState.key) {
            this._sortedData = [...this._filteredData];
            return;
        }

        if (typeof useTableSort === 'function') {
            this._sortedData = useTableSort(
                this._filteredData,
                this.sortState.key,
                this.sortState.type,
                this.sortState.dir
            );
        } else {
            console.warn('DataTable: useTableSort not found. Skipping sorting.');
            this._sortedData = [...this._filteredData];
        }
    }

    render() {
        if (!this.container) return;

        let html = '<div class="scrollable-table"><table class="table table-dark-custom"><thead><tr>';

        // Render Headers
        this.columns.forEach(col => {
            let thClass = '';
            let sortIcon = '';
            let attrs = '';

            if (col.sortable) {
                thClass = 'sortable';
                // Direct inline click handler to completely avoid any bubbling or detachment DOM issues
                const jsCall = `window._tableSortHandler('${this.containerId}', '${col.key}', '${col.type || 'text'}')`;
                attrs = `data-sort-key="${col.key}" data-sort-type="${col.type || 'text'}" style="cursor:pointer; user-select:none;" onclick="${jsCall}"`;

                if (this.sortState.key === col.key) {
                    thClass += ' active-sort';
                    sortIcon = this.sortState.dir === 'asc' ? ' <i class="fas fa-sort-up"></i>' : ' <i class="fas fa-sort-down"></i>';
                } else {
                    sortIcon = ' <i class="fas fa-sort text-muted" style="opacity:0.3;"></i>';
                }
            }

            if (col.className) {
                thClass += ` ${col.className}`;
            }

            html += `<th class="${thClass}" ${attrs}>${col.label}${sortIcon}</th>`;
        });
        html += '</tr></thead><tbody>';

        // Render Rows
        if (this._sortedData.length === 0) {
            html += `<tr><td colspan="${this.columns.length}" class="text-center text-muted py-4">${this.emptyMessage}</td></tr>`;
        } else {
            this._sortedData.forEach((row, idx) => {
                html += this.renderRow(row, idx);
            });
        }

        html += '</tbody></table></div>';

        this.container.innerHTML = html;

        // Execute any post-render callbacks provided by columns
        if (typeof this.onRenderComplete === 'function') {
            this.onRenderComplete(this._sortedData);
        }
    }
}

// Make globally available
window.DataTable = DataTable;
window._tableInstances = window._tableInstances || {};

window._tableSortHandler = function (containerId, sortKey, sortType) {
    console.log('[DataTable inline] Sort triggered:', containerId, sortKey, sortType);
    const tbl = window._tableInstances[containerId];
    if (!tbl) return;

    if (tbl.sortState.key === sortKey) {
        if (tbl.sortState.dir === 'asc') tbl.sortState.dir = 'desc';
        else if (tbl.sortState.dir === 'desc') {
            tbl.sortState.key = null;
            tbl.sortState.dir = null;
            tbl.sortState.type = null;
        }
    } else {
        tbl.sortState = { key: sortKey, dir: 'asc', type: sortType };
    }

    tbl.applySort();
    tbl.render();

    if (typeof tbl.onSortChange === 'function') {
        tbl.onSortChange(tbl._sortedData);
    }
};
