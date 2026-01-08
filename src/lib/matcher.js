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

    // Published date range
    if (query.published_from && cve.published < query.published_from) return false;
    if (query.published_to && cve.published > query.published_to) return false;

    // Modified date range
    if (query.modified_from && cve.lastModified < query.modified_from) return false;
    if (query.modified_to && cve.lastModified > query.modified_to) return false;

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
