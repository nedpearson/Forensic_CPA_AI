# GlobalFilterState Usage Guide

This guide describes how to read, write, and serialize filters using the canonical `GlobalFilterStore`.

## 1. Including the Store and Types
Ensure the shared scripts are loaded in your HTML before your main application logic:
```html
<script src="/shared/types/index.js"></script>
<script src="/shared/url.js"></script>
<script src="/shared/store.js"></script>
```

This exposes `window.DrilldownTarget`, `window.GlobalFilterStore`, `window.serializeFilters`, and `window.hydrateFilters`.

## 2. Initializing the Store
Instantiate the store globally in your application:
```javascript
// 1. Hydrate filters automatically from the current URL
const initialFilters = hydrateFilters(window.location.search);

// 2. Instantiate the global store
window.FilterStore = new GlobalFilterStore(initialFilters);
```

## 3. Reading Filters
Instead of manually scraping DOM elements, subscribe your data-fetching functions to the store. 

```javascript
FilterStore.subscribe((filters) => {
    // 1. This callback fires automatically whenever filters change.
    
    // 2. Update the URL query string continuously for shareable states
    const qs = serializeFilters(filters);
    window.history.replaceState(null, '', '?' + qs);
    
    // 3. Trigger your reload functions
    loadTransactions();
    loadDashboard();
});

// If you just need to instantly grab the current state synchronously:
const currentFilters = FilterStore.getState();
```

## 4. Writing Filters (Drilldowns & UI Events)
Any UI interaction that changes a filter parameter must call `update()`, `replace()`, or `clear()`. The store then automatically notifies all subscribers.

```javascript
// Example A: Updating a single filter
// (e.g., user selects a category from a dropdown)
function onCategorySelect(categoryName) {
    FilterStore.update({ category: categoryName });
}

// Example B: Clearing a specific filter
// (passing null, undefined, or an empty string removes the key)
function clearCategory() {
    FilterStore.update({ category: null });
}

// Example C: Executing a full Drilldown
// (wiping out old contextual filters and applying new ones)
function drilldownToCardholder(cardholderName) {
    FilterStore.replace({ 
        cardholder: cardholderName,
        view_mode: 'all'
    });
    
    navigateTo(DrilldownTarget.TRANSACTIONS);
}
```
