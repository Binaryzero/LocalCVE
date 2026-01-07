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

    // Should verify we see the specific CVE or at least no "Error" text
    await expect(page.getByText('CVE-2002-2211')).toBeVisible();
});
