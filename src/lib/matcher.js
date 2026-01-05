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
        const inId = cve.id.toLowerCase().includes(searchText);
        const inDesc = cve.description.toLowerCase().includes(searchText);
        const inRefs = (cve.references || []).some(r => r.toLowerCase().includes(searchText));

        if (!inId && !inDesc && !inRefs) return false;
    }

    // Published date range
    if (query.published_from && cve.published < query.published_from) return false;
    if (query.published_to && cve.published > query.published_to) return false;

    // Modified date range
    if (query.modified_from && cve.lastModified < query.modified_from) return false;
    if (query.modified_to && cve.lastModified > query.modified_to) return false;

    // CVSS Score
    const score = cve.score || 0;
    if (query.cvss_min !== undefined && score < query.cvss_min) return false;
    if (query.cvss_max !== undefined && score > query.cvss_max) return false;

    // KEV
    if (query.kev === true && cve.kev !== true) return false;

    // EPSS (if integration exists later)
    if (query.epss_min !== undefined) {
        const epss = cve.epssScore || 0;
        if (epss < query.epss_min) return false;
    }

    return true;
}
