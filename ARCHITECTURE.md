# Architecture and threat model

The CLI receives an explicit local source root. It uses a bounded read-only walk and Python AST parsing, then emits JSON or SARIF. External JS/TS SARIF is parsed as untrusted data and represented with a separate origin marker. No source code or external results are executed.

```mermaid
flowchart LR
  P[Authorized Python source] --> A[Bounded AST scan]
  S[External JS/TS SARIF] --> I[Bounded import]
  A --> F[Heuristic findings]
  I --> F
  F --> R[JSON or SARIF report]
```

Threats include malicious source execution, symlink traversal, parser exhaustion, false positive vulnerability claims, and secret leakage from imported SARIF messages. Controls include AST-only parsing, nofollow file opens, depth/file/byte caps, source-free reports, imported-message discard, and explicit heuristic labels. There is no API, database, or frontend in this offline milestone.
