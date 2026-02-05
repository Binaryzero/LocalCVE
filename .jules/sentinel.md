## 2025-02-05 - SQL LIKE Wildcard Injection and Information Leakage in API Responses
**Vulnerability:** Unsanitized user input in SQL `LIKE` queries for vendor and product searches, and verbose 500 error messages leaking internal details (`err.message`).
**Learning:** Even with parameterized queries, `LIKE` clauses remain vulnerable to wildcard injection if `%` and `_` are not escaped. Additionally, exposing `err.message` in production 500 responses is a common source of information leakage.
**Prevention:** Always use `escapeLikePattern()` with `ESCAPE '\\'` for user-controlled input in `LIKE` clauses. Standardize 500 responses to use generic error messages while logging full details to the server console.
