import { test, expect } from '@playwright/test';

test('has title', async ({ page }) => {
    await page.goto('/');

    // Expect a title "to contain" a substring.
    await expect(page).toHaveTitle(/Local CVE Tracker/);
});

test('navigation tabs work', async ({ page }) => {
    await page.goto('/');

    // Check Dashboard is active by default (assuming some UI indication or just text presence)
    await expect(page.getByText('Critical Vulnerabilities')).toBeVisible();

    // Navigate to CVEs
    await page.click('text=CVEs');
    // Check for CVE list content, e.g. "Severity" column or filter input
    await expect(page.getByPlaceholder('Search CVE ID or description...')).toBeVisible();

    // Navigate to Watchlists
    await page.click('text=Watchlists');
    // Check for "New Watchlist" button
    await expect(page.getByText('New Watchlist', { exact: true })).toBeVisible();

    // Navigate to Alerts
    await page.click('text=Alerts');
    // Navigate to Jobs
    await page.click('text=Jobs');
    await expect(page.getByText('Ingestion Jobs')).toBeVisible();
});

test('search works with hyphens', async ({ page }) => {
    await page.goto('/');
    await page.click('text=CVEs');
    await expect(page.getByPlaceholder('Search CVE ID or description...')).toBeVisible();

    const searchInput = page.getByPlaceholder('Search CVE ID or description...');
    await searchInput.fill('CVE-2002-2211');
    // Wait for debounce or network
    await page.waitForTimeout(1000);

    // Should verify we see the specific CVE or at least no "Error" text
    await expect(page.getByText('CVE-2002-2211')).toBeVisible();
});
