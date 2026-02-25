// shared/drilldown.js

/**
 * Calculates the next FilterSchema based on the current state and a DrilldownEvent payload.
 * Only applies explicitly provided filters, wiping out others unless they're structurally preserved (like view_mode).
 * 
 * @param {Object} currentState 
 * @param {Object} event { target: DrilldownTarget, filters: Partial<FilterSchema> }
 * @returns {Object} nextFilters
 */
function drilldownReducer(currentState, event) {
    const nextFilters = { ...event.filters };

    // View mode is considered sticky and inherits from parent unless explicitly overridden
    if (!nextFilters.view_mode && currentState.view_mode) {
        nextFilters.view_mode = currentState.view_mode;
    }

    // date_preset inherits if we aren't replacing the date logically
    if (!nextFilters.date_preset && !nextFilters.date_from && !nextFilters.date_to && currentState.date_preset) {
        nextFilters.date_preset = currentState.date_preset;
    }

    return nextFilters;
}

/**
 * Manages breadcrumb history pushing and popping
 */
class BreadcrumbStore {
    constructor() {
        this.history = []; // Array of { label, target, filters }
        this.listeners = new Set();
    }

    push(label, target, currentFilters) {
        // Prevent dupes if navigating to exact same target with exact same label (optional UX polish)
        const last = this.history[this.history.length - 1];
        if (last && last.label === label && last.target === target) {
            return;
        }

        this.history.push({
            label,
            target,
            // Snapshot a copy
            filters: { ...currentFilters }
        });
        this.notify();
    }

    pop(index) {
        if (index < 0 || index >= this.history.length) return null;
        const snapshot = this.history[index];
        // Truncate history after the popped index
        this.history = this.history.slice(0, index);
        this.notify();
        return snapshot;
    }

    clear() {
        this.history = [];
        this.notify();
    }

    getHistory() {
        return [...this.history];
    }

    subscribe(listener) {
        this.listeners.add(listener);
        return () => this.listeners.delete(listener);
    }

    notify() {
        const h = this.getHistory();
        this.listeners.forEach(cb => cb(h));
    }
}

/**
 * Factory for creating a drilldown handler bound to a specific component.
 * Mirrors the useDrilldown hook idiom.
 * 
 * @param {Object} config
 * @param {string} config.sourceTab - Source tab reporting the event (e.g. 'dashboard')
 * @param {string} config.widgetId - Widget initiating the drilldown (e.g. 'category-chart')
 * @param {string} config.defaultTarget - Fallback DrilldownTarget
 * @param {Function} config.onNavigate - Callback(target, nextFilters) to perform the actual UI transition
 * @param {Function} config.onLogEvent - Callback(eventRecord) to log the telemetry
 * @param {Function} config.getState - Callback returning the current global filters
 * @param {BreadcrumbStore} config.breadcrumbStore
 * @param {string} config.breadcrumbLabel - String to push into the breadcrumb for the CURRENT view
 */
function createDrilldownHandler(config) {
    return function emitDrilldown(event) {
        const target = event.target || config.defaultTarget;

        // 1. Calculate next state
        const currentState = config.getState();
        const nextFilters = drilldownReducer(currentState, event);

        // 2. Prepare telemetry payload
        const telemetryRecord = {
            source_tab: config.sourceTab,
            widget_id: config.widgetId,
            target: target,
            filters_applied: JSON.stringify(event.filters),
            metadata: JSON.stringify(event.metadata || {})
        };

        // 3. Log event
        if (config.onLogEvent) {
            config.onLogEvent(telemetryRecord);
        }

        // 4. Push current state into breadcrumbs so we can return
        if (config.breadcrumbStore && config.breadcrumbLabel) {
            config.breadcrumbStore.push(config.breadcrumbLabel, config.sourceTab, currentState);
        }

        // 5. Fire navigation (updates FilterStore internally via integration layer)
        config.onNavigate(target, nextFilters);
    };
}

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { drilldownReducer, BreadcrumbStore, createDrilldownHandler };
} else if (typeof window !== 'undefined') {
    window.drilldownReducer = drilldownReducer;
    window.BreadcrumbStore = BreadcrumbStore;
    window.createDrilldownHandler = createDrilldownHandler;
}
