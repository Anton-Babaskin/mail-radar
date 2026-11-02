# Primary sources and version-sensitive semantics

Reviewed 2026-11-02. These references explain decisions; they do not establish
the installed package versions or validate a production host. Direct opens of
some Postfix pages returned HTTP 402 in the browsing environment; their indexed
primary-source text was retrieved through the web-search connector instead.

* [Postfix postqueue(1)](https://www.postfix.org/postqueue.1.html): JSON Lines
  listing is available from Postfix 3.1. It supplies queue name, ID and arrival
  time. The queue changes during enumeration, so entries can repeat or be
  missed. IDs can be reused and do not identify messages across instances.
  Radar handles unknown/malformed records as incomplete and uses text fallback
  only when JSON is unsupported, not after arbitrary queue errors.
* [Postfix SMTP policy delegation](https://www.postfix.org/SMTPD_POLICY_README.html)
  and [standard configurations](https://www.postfix.org/STANDARD_CONFIGURATION_README.html):
  Postfix 2.10+ supports a separate relay restriction chain. Absence of a guard
  in recipient restrictions alone is therefore not proof of an open relay.
* [Postfix postconf(5)](https://www.postfix.org/postconf.5.html):
  `parent_domain_matches_subdomains` controls whether the plain parent-domain
  key applies to subdomains for the named feature, including `smtpd_access_maps`.
  Radar examines the actual value; exact `postmap -q` output is not represented
  as a complete SMTP access evaluation. See also
  [access(5)](https://www.postfix.org/access.5.html) and
  [SMTP access control](https://www.postfix.org/SMTPD_ACCESS_README.html).
* [Postgrey source](https://github.com/schweikert/postgrey/blob/master/postgrey),
  inspected blob `2a865b7f1f56d37f6b497f6df3a2ee50310d8ad0`:
  plain client hostnames are suffix matched at a domain boundary; address/CIDR
  and Perl-regex rules are separate paths. Radar does not execute Perl patterns
  or equate client domains with envelope From. Version-specific ambiguous
  address shorthand requires evidence, not extrapolation from a comment.
* [Dovecot fetch reference](https://doc.dovecot.org/2.4.1/core/man/doveadm-fetch.1.html)
  distinguishes received/saved/sent dates and named header fields. Its user
  selector supports wildcards, which Radar rejects to preserve targeted scope.
  The [Dovecot 2.3 command documentation](https://doc.dovecot.org/2.3/admin_manual/doveadm_http_api/)
  also lists selected header/date/mailbox metadata fields. The current adapter
  requires supported CLI JSON output; an unsupported output shape is UNKNOWN,
  not evidence of non-delivery. No claim of exhaustive 2.4 integration testing
  follows from consulting that reference.
* [RFC 5322 sections 3.6.1 and 3.6.7](https://www.rfc-editor.org/rfc/rfc5322.html):
  Date describes the creator's origination time and is not the actual transport
  time. Received is a trace field. A difference between their clocks cannot by
  itself attribute delay to this server or to greylisting.
* [MIAB setup/start.sh at 8c032705ae78daa237cd77affcc5087ca68e3a15](https://github.com/mail-in-a-box/mailinabox/blob/8c032705ae78daa237cd77affcc5087ca68e3a15/setup/start.sh#L45):
  lines 47–50 create `/usr/local/bin/mailinabox` as a wrapper sourcing setup.
  Radar never invokes it for version/help. Git metadata is read without shell
  evaluation. Reading the upstream source did not execute setup.

* [Spamhaus public DNSBL usage](https://www.spamhaus.org/faqs/dnsbl-usage/):
  public ZEN listed replies are `127.0.0.{2,3,4,9,10,11}`; reserved or service
  errors are not listings. Positive/negative operational controls are required
  because some public resolver paths synthesize NXDOMAIN. Radar checks controls
  before interpreting a target response and reports UNKNOWN if they fail.
* [Spamhaus DBL](https://www.spamhaus.org/faqs/domain-blocklist/): public domain
  codes and domain-specific controls differ from IP ZEN. Radar distinguishes
  the two kinds and treats unknown/service codes as UNKNOWN. The
  [DQS zone contract](https://docs.spamhaus.com/datasets/docs/source/10-data-type-documentation/datasets/040-zones.html)
  is not silently substituted for the public-zone contract.
* [MIAB v78 backup implementation](https://github.com/mail-in-a-box/mailinabox/blob/v78/management/backup.py):
  `backup_status` uses collection/listing operations and credential environment,
  rather than a lightweight versioned success artifact usable by Radar. Radar
  does not invoke that backup script to turn a health check green; last success
  remains UNKNOWN without independent evidence.

The implementation deliberately uses a narrower DNSBL provider list than
legacy v3.0 rather than guessing a uniform access/error contract for unrelated
operators. Public resolver DNSBL failure is not a clean result.
