# Security

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's private vulnerability reporting (the
"Report a vulnerability" button on the repository's Security tab), not in a public issue. You will
get an answer within a week, and a fix or a plan for one before anything is disclosed.

Reports are especially welcome about:

- a query, dashboard or other reader that zeroreads judges unable to read lines it can read (the rule
  would remove lines that someone needs);
- values from logs or queries that reach an emitted runtime configuration unescaped;
- credentials that appear in reports, rules files or verify output.

## Supported versions

Security fixes go into the latest release.

## What zeroreads touches

zeroreads reads from the Loki, Grafana and OpenSearch you configure, with the credentials you give it
through environment variables. It writes only when you ask it to: `rewrite -apply` updates the stored
Grafana objects and Loki ruler groups it rewrote. It sends nothing anywhere else.
