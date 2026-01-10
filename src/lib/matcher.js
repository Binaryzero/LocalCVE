/**
 * Converts a relative date preset to absolute date range.
 * @param {string} relativePeriod - 'today', 'last_7_days', 'last_30_days', 'last_90_days'
 * @returns {{ from: string, to: string | undefined }} ISO date strings (YYYY-MM-DD)
 */
export function getDateRangeFromRelative(relativePeriod) {
    const now = new Date();
    // Use local date parts to avoid timezone issues
    const formatDate = (d) => {
        const year = d.getFullYear();
        const month = String(d.getMonth() + 1).padStart(2, '0');
        const day = String(d.getDate()).padStart(2, '0');
        return `${year}-${month}-${day}`;
    };
    const todayStr = formatDate(now);

    switch (relativePeriod) {
        case 'today':
            return { from: todayStr, to: undefined };
        case 'last_7_days': {
            const from = new Date(now);
            from.setDate(from.getDate() - 7);
            return { from: formatDate(from), to: todayStr };
        }
        case 'last_30_days': {
            const from = new Date(now);
            from.setDate(from.getDate() - 30);
            return { from: formatDate(from), to: todayStr };
        }
        case 'last_90_days': {
            const from = new Date(now);
            from.setDate(from.getDate() - 90);
            return { from: formatDate(from), to: todayStr };
        }
        default:
            return { from: undefined, to: undefined };
    }
}

/**
 * Matches a CVE object against a query model.
 * @param {Object} cve - The normalized CVE object.
 * @param {Object} query - The QueryModel from a watchlist.
 * @returns {boolean}
 */
export function matchesQuery(cve, query) {
    if (!query) return false;

    // Text search (case insensitive)
    if (query.text) {
        const searchText = query.text.toLowerCase();
        const inId = cve.id ? cve.id.toLowerCase().includes(searchText) : false;
        const inDesc = cve.description ? cve.description.toLowerCase().includes(searchText) : false;
        // Handle both old format (string[]) and new format ({url, tags}[])
        const inRefs = (cve.references || []).some(r => {
            if (!r) return false;
            const url = typeof r === 'string' ? r : r.url;
            return url ? url.toLowerCase().includes(searchText) : false;
        });

        if (!inId && !inDesc && !inRefs) return false;
    }

    // Published date range - prefer relative dates if specified (truly dynamic)
    let publishedFrom = query.published_from;
    let publishedTo = query.published_to;
    if (query.published_relative) {
        const range = getDateRangeFromRelative(query.published_relative);
        publishedFrom = range.from;
        publishedTo = range.to;
    }
    if (publishedFrom && cve.published < publishedFrom) return false;
    if (publishedTo && cve.published > publishedTo) return false;

    // Modified date range - prefer relative dates if specified (truly dynamic)
    let modifiedFrom = query.modified_from;
    let modifiedTo = query.modified_to;
    if (query.modified_relative) {
        const range = getDateRangeFromRelative(query.modified_relative);
        modifiedFrom = range.from;
        modifiedTo = range.to;
    }
    if (modifiedFrom && cve.lastModified < modifiedFrom) return false;
    if (modifiedTo && cve.lastModified > modifiedTo) return false;

    // CVSS Score - primary score (backward compatibility)
    const primaryScore = cve.score || 0;
    if (query.cvss_min !== undefined && primaryScore < query.cvss_min) return false;
    if (query.cvss_max !== undefined && primaryScore > query.cvss_max) return false;

    // Version-specific CVSS filtering
    // CVSS v2 filtering
    if (query.cvss2_min !== undefined) {
        const cvss2Score = cve.cvss2Score || 0;
        if (cvss2Score < query.cvss2_min) return false;
    }
    if (query.cvss2_max !== undefined) {
        const cvss2Score = cve.cvss2Score || 0;
        if (cvss2Score > query.cvss2_max) return false;
    }

    // CVSS v3.0 filtering
    if (query.cvss30_min !== undefined) {
        const cvss30Score = cve.cvss30Score || 0;
        if (cvss30Score < query.cvss30_min) return false;
    }
    if (query.cvss30_max !== undefined) {
        const cvss30Score = cve.cvss30Score || 0;
        if (cvss30Score > query.cvss30_max) return false;
    }

    // CVSS v3.1 filtering
    if (query.cvss31_min !== undefined) {
        const cvss31Score = cve.cvss31Score || 0;
        if (cvss31Score < query.cvss31_min) return false;
    }
    if (query.cvss31_max !== undefined) {
        const cvss31Score = cve.cvss31Score || 0;
        if (cvss31Score > query.cvss31_max) return false;
    }

    // KEV
    if (query.kev === true && cve.kev !== true) return false;

    // EPSS (if integration exists later)
    if (query.epss_min !== undefined) {
        const epss = cve.epssScore || 0;
        if (epss < query.epss_min) return false;
    }

    return true;
}
