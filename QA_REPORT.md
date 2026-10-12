# LAI Online 1.1 - Verification report

Prepared 12 October 2026. Test platform: Linux / Python 3.13 / Chromium.
All accounts, records, passwords and files used by tests were synthetic.

## Completed checks

- 48 existing local regression checks passed against the unchanged local HTTP
  implementation in an isolated temporary data directory.
- 82 online WSGI checks passed. They include the business workflows, role and
  record permissions, CSRF, HTTPS-origin restrictions, protected first setup,
  host-prefixed Secure cookie output, bounded request bodies, rate limiting,
  concurrent stale-update protection, single-process enforcement, and migration
  of a database produced by the original v1 core with its account and attachment.
- 6 browser/UI checks passed: protected setup form, account creation and dashboard,
  all 13 navigation screens, a 390-pixel mobile layout, disabled trainer signup,
  and absence of JavaScript page errors in this tested flow.
- 6 operational/configuration checks passed: offline snapshot restore, active-lock
  rejection, invalid-snapshot preservation, missing-secret failure, public HTTP
  rejection and syntactic YAML/configuration assertions.
- Python compilation and JavaScript syntax validation passed.

Counts are checks, not distinct security guarantees. The WSGI suite repeats some
business cases from the local regression suite; do not describe the total as a
count of unique audited features.

## Test-method boundaries

The WSGI suite calls the real online application through wsgiref's WSGI protocol
validator. HTTPS is represented in the request environment to check application
behavior. This does not create or test an actual TLS connection.

Chromium in this execution environment blocks URL navigation. UI testing used
the real HTML, CSS and JavaScript with set_content and a Python binding relaying
API calls to a separate loopback WSGI HTTP server. Browser-native cookie policy,
public navigation and TLS were not tested by that UI bridge. Session cookie
header requirements were separately asserted in the WSGI suite.

Docker is unavailable here. An attempt to install the pinned Gunicorn dependency
could not download it because network package retrieval was unavailable. Thus
Gunicorn execution, Docker builds, Caddy configuration execution, Render API
validation/deployment, public DNS, firewall rules and certificate issuance were
NOT tested. Deployment files were reviewed against the linked primary docs and
YAML syntax was parsed locally; this is not an actual provider deployment.

No public URL was created. No host or registrar was changed. No paid service was
purchased. No real institute data was migrated by this preparation session.

## Required production acceptance checks

The hosting operator must build/start the selected deployment; verify HTTPS and
HTTP redirection; test two separate devices/accounts; check persistent records
after service restart; verify file downloads; export and restore an actual test
snapshot; confirm an external encrypted backup; and review permitted data region,
permissions and logging before using real personal or financial data.

This was not a penetration test, high-load test, legal compliance audit or
high-availability/disaster-recovery certification. The online build is designed
for one process / one instance. It has no MFA, malware scanner or offsite backup
integration. See README_DEPLOY.md for architecture, limitations and operations.

## Re-run the included automated suites

```sh
python3 tests/test_local_regression.py
python3 tests/test_online.py
```

## Online WSGI checks observed

1. Setup rejects missing secret
2. Setup rejects incorrect secret
3. Unauthorized setup leaves the database empty
4. Empty database requires setup
5. Unauthenticated records blocked
6. First-run setup cannot be repeated
7. Admin login and secure session
8. CSRF, DNS rebinding Host and cross-origin writes blocked
9. Temporary passwords must be changed before writes
10. Employee cannot administer users or download database
11. Last active administrator cannot be demoted
12. Employee only sees own assigned tasks
13. Direct ID access cannot bypass record scope
14. Completion and unproven review cannot be forged
15. Employees cannot move deadlines, relax acceptance or cancel assigned tasks
16. Stale edits are rejected without overwriting
17. Attachment content is persisted
18. Attachment access obeys parent record scope
19. Manager approval closes proven task
20. Approved tasks are protected from silent edits
21. Manager cannot self-approve assigned task
22. Approval creates one recurring successor
23. Duplicate approval cannot repeat the recurrence
24. Trainer can only view assigned courses
25. Staff course view redacts trainer fees and marketing
26. Course seat capacity enforced on server
27. Trainer sees attendance but no contact or fee
28. Trainer can record attendance and outcome
29. Certificate status requires attendance and passing result
30. Service can track eligible certificate issuance
31. Financial entries private and immutable
32. Overcollection against a registration is rejected
33. Refund bounded by original unrefunded amount
34. Paid registration cannot be moved to another course
35. Course settlement avoids trainer double-counting
36. Approved content requires explicit reopening
37. Publication can be tracked after approval
38. Manual result updates require evidence
39. Leave approval separated from applicant
40. Clock-in/out uses server time and prevents duplicate punches
41. Won lead creates linked service handoff only once
42. Service resolution cannot omit outcome
43. CSV formula injection hardened
44. Audit payloads do not leak financial data to trainer
45. Self-registered trainer requires admin activation
46. Consistent SQLite backup produced
47. Restore requires password and valid SQLite snapshot
48. Restore swaps data and invalidates sessions
49. Backup/restore includes attachments
50. All four departments present
51. No internal server errors
52. Application identifies the online build
53. Session cookie has host prefix and transport protections
54. Session secret is absent from response JSON
55. Setup token is never returned
56. Forwarded host cannot bypass host allowlist
57. Cross-site fetch rejected
58. Plain HTTP rejected outside loopback development
59. Legacy non-host session cookie rejected on HTTPS
60. Writes require the application header
61. New passwords require at least 12 characters
62. Source, settings and database files are not public routes
63. Unauthorized uploads rejected before reading their body
64. Ordinary body size limit enforced before read
65. Online restore size limit enforced before read
66. Employee restore rejected before reading content
67. Malformed JSON returns a controlled 400
68. Non-object JSON rejected
69. Public health endpoint exposes no record data
70. HEAD returns headers without a body
71. Unsupported methods rejected
72. Indexing discouraged without claiming it is authentication
73. HSTS and CSP are present on secure responses
74. Trainer signup can be disabled
75. Disabled public signup enforced server-side
76. Simultaneous stale edits cannot overwrite one another
77. Second online process is rejected
78. Original local v1 account and records migrate
79. Local v1 attachment migrates
80. Online snapshot can restore back after migration
81. Public setup attempts are rate limited
82. No internal errors in online functional run

## Browser checks observed

- Protected setup field renders in Chromium
- Browser creates an administrator and opens the online dashboard
- All 13 navigation screens render
- 390px mobile dashboard fits viewport
- Public trainer signup hidden when disabled
- No JavaScript page errors in the tested flow

## Operational checks observed

- Offline restore validates and imports a v1 snapshot
- Offline restore refuses an active application lock
- Invalid offline snapshot leaves existing data intact
- Uninitialized deployment fails closed without a strong setup secret
- Development HTTP flag cannot enable HTTP on a public domain
- Deployment YAML parses and preserves private backend, one instance and persistent data settings
