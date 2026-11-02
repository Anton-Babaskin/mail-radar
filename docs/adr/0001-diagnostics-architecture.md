# ADR 0001: shared local diagnostics with a Python standard-library core

Date: 2026-11-02. Status: accepted for this working branch.

## Context

The audited baseline is `d1add36326b537bc414859e681e3128fb643b515`.
Its Bash script has useful service, disk, queue, mail-flow and security checks.
The defects are established by the source, not by its size or authorship:
GNU-awk-specific time parsing silently loses data on another awk; independent
sections read different log windows; queue and DNS command failures become
successful empty results. Grepping arbitrary text cannot safely model queue
lifecycles, reinjection or the trust boundary of Postfix fields.

## Decision

Keep two small Bash launchers (`mail-radar`, compatible `miab-radar`) and an
explicit staged installer. Use Python 3.9+ and its standard library for a shared
CLI/menu, timestamp handling, bounded source ingestion, event correlation,
findings, JSON and process runner. No pip installation is needed.

Modules separate responsibilities: `cli` assembles the workflow; `model` owns
findings/evidence and serialization; `runner` owns allowed command actions and
process lifetime; `logs` owns ingestion and correlation; `checks` owns host and
configuration rules; `mailstore` owns targeted Dovecot metadata access. Menu and
automation select the same workflows.

External checks use argv lists, explicit limits, return codes and captured
stderr. Read-only is an action boundary: `postmap -q` can be permitted while a
map rebuild cannot. MIAB setup/update wrappers are never a version probe.
The diagnostic runner does not invoke sibling projects wholesale or fetch code
at runtime. Active network probes are explicit. Missing permissions or commands
produce UNKNOWN; limits affect report completeness.

## Alternatives and consequences

Repairing only Bash would preserve one-file delivery but leave complex event
state, offsets and structured output spread across pipelines. A line-by-line
translation would preserve those errors. A new framework, database, web service
or mandatory Docker deployment would add operational requirements without
helping the SSH-local task.

The chosen package is a larger distribution than one Bash file and needs
Python 3.9+, supplied as Python 3.10 on Ubuntu 22.04. `install.sh` copies the
package to `PREFIX/lib/mail-radar/mailradar` and both launchers to `PREFIX/bin`;
`DESTDIR` supports isolated packaging. Source checkout execution remains
available. Existing numeric period syntax and exit codes 0/1/2 are retained;
JSON is a new versioned Radar contract, with an explicit FleetOps mapping
rather than an unsupported drop-in compatibility claim.

Tests must establish behavior at the workflow boundary, including missing
tools, incomplete logs, untrusted fields and forbidden commands. Passing unit
fixtures does not establish correctness on every deployed mail stack.
