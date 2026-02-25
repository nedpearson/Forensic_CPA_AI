// shared/store.js

/**
 * GlobalFilterStore
 * Manages the canonical FilterSchema state, event subscriptions (pub/sub),
 * and applying partial updates.
 */
class GlobalFilterStore {
    /**
     * @param {Object} initialState 
     */
    constructor(initialState = {}) {
        this.state = { ...initialState };
        this.listeners = new Set();
    }

    /**
     * Get current state snapshot
     * @returns {Object} copy of state
     */
    getState() {
        return { ...this.state };
    }

    /**
     * Apply partial filter updates. Values explicitly set to null/undefined or empty string will be deleted.
     * @param {Object} updates 
     */
    update(updates) {
        let changed = false;
        for (const [key, value] of Object.entries(updates)) {
            if (value === null || value === undefined || value === '') {
                if (key in this.state) {
                    delete this.state[key];
                    changed = true;
                }
            } else if (this.state[key] !== String(value)) {
                this.state[key] = String(value);
                changed = true;
            }
        }
        if (changed) {
            this.notify();
        }
    }

    /**
     * Replace entire state
     * @param {Object} newState 
     */
    replace(newState) {
        this.state = {};
        for (const [key, val] of Object.entries(newState)) {
            if (val !== null && val !== undefined && val !== '') {
                this.state[key] = String(val);
            }
        }
        this.notify();
    }

    /**
     * Clear all filters except view_mode (which is sticky UI state)
     */
    clear() {
        const viewMode = this.state.view_mode;
        this.state = {};
        if (viewMode) this.state.view_mode = viewMode;
        this.notify();
    }

    /**
     * Subscribe to state changes
     * @param {Function} listener 
     * @returns {Function} unsubscribe function
     */
    subscribe(listener) {
        this.listeners.add(listener);
        return () => this.listeners.delete(listener);
    }

    notify() {
        const snapshot = this.getState();
        this.listeners.forEach(listener => listener(snapshot));
    }
}

// Export for Node.js tests & attach to window for browser
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { GlobalFilterStore };
} else if (typeof window !== 'undefined') {
    window.GlobalFilterStore = GlobalFilterStore;
}
