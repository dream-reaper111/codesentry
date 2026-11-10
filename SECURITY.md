# Security model

Scan only repositories you are authorized to review. CodeSentry does not import or execute scanned modules. It does not access package registries or run build scripts. Paths and finding locations may reveal sensitive architecture; protect output. Imported SARIF is untrusted and its message text is discarded.

Pattern matches are not confirmed vulnerabilities. The current scanner has no taint analysis, no JavaScript/TypeScript parser, no authenticated server, and no audit database. Avoid using results as an automatic production CI gate until rule quality and false-positive handling are reviewed.
