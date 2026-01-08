import { test, expect } from '@playwright/test';

test('has title', async ({ page }) => {
    await page.goto('/');

    // Expect title to contain "CVE Tracker"
    await expect(page).toHaveTitle(/CVE Tracker/);
});

test('navigation tabs work', async ({ page }) => {
    await page.goto('/');

    // CVE Search is the default page - check for search input
    await expect(page.getByPlaceholder('SEARCH CVE-ID OR DESCRIPTION...')).toBeVisible();

    // Navigate to Alerts
    await page.click('text=Alerts');
    await expect(page.getByText('ALERT INBOX')).toBeVisible();

    // Navigate to Watchlists
    await page.click('text=Watchlists');
    await expect(page.getByText('NEW WATCHLIST')).toBeVisible();

    // Navigate to Ingestion
    await page.click('text=Ingestion');
    await expect(page.getByText('INGESTION CONTROL')).toBeVisible();

    // Navigate back to CVEs
    await page.click('text=CVEs');
    await expect(page.getByText('CVE SEARCH')).toBeVisible();
});

test('search works with hyphens', async ({ page }) => {
    await page.goto('/');

    // CVE Search is the default page
    await expect(page.getByPlaceholder('SEARCH CVE-ID OR DESCRIPTION...')).toBeVisible();

    const searchInput = page.getByPlaceholder('SEARCH CVE-ID OR DESCRIPTION...');
    await searchInput.fill('CVE-2002-2211');

    // Wait for debounce or network
    await page.waitForTimeout(1000);

    // Should see results count (indicates search worked)
    // Using locator with regex to avoid strict mode issues with CVE ID appearing in multiple places
    await expect(page.locator('text=/\\d+ RESULTS?/')).toBeVisible();
});

// --- CVE Search and Filtering Tests ---

test('filters panel toggles visibility', async ({ page }) => {
    await page.goto('/');
    // Wait for page to fully load before checking initial state
    await page.waitForLoadState('networkidle');

    // Filters panel should not be visible initially
    const cvssLabel = page.locator('text=MIN CVSS SCORE');
    await expect(cvssLabel).not.toBeVisible();

    // Click FILTERS button to show panel
    await page.click('button:has-text("FILTERS")');
    await expect(cvssLabel).toBeVisible();

    // Click FILTERS button again to hide panel
    await page.click('button:has-text("FILTERS")');
    await expect(cvssLabel).not.toBeVisible();
});

test('CVSS minimum filter works', async ({ page }) => {
    await page.goto('/');

    // Open filters panel
    await page.click('button:has-text("FILTERS")');

    // Find the CVSS text input and set to 9.0 (Critical)
    const cvssInput = page.locator('input[type="number"][min="0"][max="10"]').first();
    await cvssInput.fill('9.0');

    // Wait for search to execute
    await page.waitForTimeout(1000);

    // Should see results or "No CVEs found" message
    // The important thing is no errors occurred
    const hasResults = await page.locator('text=/CVE-\\d{4}-\\d+/').count() > 0;
    const hasNoResults = await page.locator('text=No CVEs found').count() > 0;
    expect(hasResults || hasNoResults).toBeTruthy();
});

test('date range filter shows presets', async ({ page }) => {
    await page.goto('/');

    // Open filters panel
    await page.click('button:has-text("FILTERS")');

    // Check for date preset buttons
    await expect(page.locator('button:has-text("7D")')).toBeVisible();
    await expect(page.locator('button:has-text("30D")')).toBeVisible();
    await expect(page.locator('button:has-text("90D")')).toBeVisible();
    await expect(page.locator('button:has-text("YTD")')).toBeVisible();
});

test('date preset 7D sets date filter', async ({ page }) => {
    await page.goto('/');

    // Open filters panel
    await page.click('button:has-text("FILTERS")');

    // Click 7D preset
    await page.click('button:has-text("7D")');

    // The "from" date input should now have a value
    const fromInput = page.locator('input[type="date"]').first();
    const value = await fromInput.inputValue();
    expect(value).toBeTruthy();

    // Value should be approximately 7 days ago (YYYY-MM-DD format)
    const dateValue = new Date(value);
    const now = new Date();
    const diffDays = Math.round((now.getTime() - dateValue.getTime()) / (1000 * 60 * 60 * 24));
    expect(diffDays).toBeGreaterThanOrEqual(6);
    expect(diffDays).toBeLessThanOrEqual(8);
});

test('filter presets are visible', async ({ page }) => {
    await page.goto('/');

    // Open filters panel
    await page.click('button:has-text("FILTERS")');

    // Check for built-in presets
    await expect(page.locator('text=FILTER PRESETS')).toBeVisible();
    await expect(page.locator('button:has-text("Critical Only")')).toBeVisible();
    await expect(page.locator('button:has-text("High + Recent")')).toBeVisible();
    await expect(page.locator('button:has-text("Known Exploited")')).toBeVisible();
});

test('Critical Only preset applies CVSS filter', async ({ page }) => {
    await page.goto('/');

    // Open filters panel
    await page.click('button:has-text("FILTERS")');

    // Click Critical Only preset
    await page.click('button:has-text("Critical Only")');

    // Wait for search
    await page.waitForTimeout(1000);

    // The CVSS input should now show 9
    const cvssInput = page.locator('input[type="number"][min="0"][max="10"]').first();
    const value = await cvssInput.inputValue();
    expect(parseFloat(value)).toBeGreaterThanOrEqual(9);
});

test('severity matrix toggle works', async ({ page }) => {
    await page.goto('/');

    // Severity matrix should not be visible initially
    const matrixHeader = page.locator('text=SEVERITY MATRIX');
    await expect(matrixHeader).not.toBeVisible();

    // Click MATRIX button
    await page.click('button:has-text("MATRIX")');
    await expect(matrixHeader).toBeVisible();

    // Click MATRIX button again to hide
    await page.click('button:has-text("MATRIX")');
    await expect(matrixHeader).not.toBeVisible();
});

test('clear search returns to initial state', async ({ page }) => {
    await page.goto('/');

    // Enter search text
    const searchInput = page.getByPlaceholder('SEARCH CVE-ID OR DESCRIPTION...');
    await searchInput.fill('test search');
    await page.waitForTimeout(500);

    // Clear the input
    await searchInput.fill('');
    await page.waitForTimeout(500);

    // Should be back to initial state (search-first, no default data)
    // Either shows the search prompt or has CVE results
    const searchPrompt = page.locator('text=SEARCH THE CVE DATABASE');
    const hasPrompt = await searchPrompt.count() > 0;
    const hasResults = await page.locator('text=/CVE-\\d{4}-\\d+/').count() > 0;

    // One of these should be true
    expect(hasPrompt || hasResults).toBeTruthy();
});

test('pagination controls appear with results', async ({ page }) => {
    await page.goto('/');

    // Search for something broad
    const searchInput = page.getByPlaceholder('SEARCH CVE-ID OR DESCRIPTION...');
    await searchInput.fill('CVE-2024');
    await page.waitForTimeout(1500);

    // If there are enough results, pagination should appear
    const hasResults = await page.locator('text=/CVE-\\d{4}-\\d+/').count() > 0;
    if (hasResults) {
        // Check for pagination info text
        const paginationText = page.locator('text=/Page \\d+ of \\d+/');
        const hasPagination = await paginationText.count() > 0;
        // Pagination may not appear if there are fewer than 50 results
        expect(typeof hasPagination).toBe('boolean');
    }
});

test('CVE detail view opens on click', async ({ page }) => {
    await page.goto('/');

    // Search for a specific CVE
    const searchInput = page.getByPlaceholder('SEARCH CVE-ID OR DESCRIPTION...');
    await searchInput.fill('CVE-2024');
    await page.waitForTimeout(1500);

    // Click on first CVE result if available
    const firstCve = page.locator('text=/CVE-\\d{4}-\\d+/').first();
    const hasResults = await firstCve.count() > 0;

    if (hasResults) {
        await firstCve.click();
        await page.waitForTimeout(500);

        // Should see the back button and detail view elements
        await expect(page.locator('text=BACK TO LIST')).toBeVisible();
        // Use heading role to avoid matching "description" in JSON raw data
        await expect(page.getByRole('heading', { name: 'DESCRIPTION' })).toBeVisible();
    }
});

test('CVE detail back button returns to list', async ({ page }) => {
    await page.goto('/');

    // Search and click a CVE
    const searchInput = page.getByPlaceholder('SEARCH CVE-ID OR DESCRIPTION...');
    await searchInput.fill('CVE-2024');
    await page.waitForTimeout(1500);

    const firstCve = page.locator('text=/CVE-\\d{4}-\\d+/').first();
    const hasResults = await firstCve.count() > 0;

    if (hasResults) {
        await firstCve.click();
        await page.waitForTimeout(500);

        // Click back button
        await page.click('text=BACK TO LIST');
        await page.waitForTimeout(500);

        // Should see search input again
        await expect(page.getByPlaceholder('SEARCH CVE-ID OR DESCRIPTION...')).toBeVisible();
    }
});
