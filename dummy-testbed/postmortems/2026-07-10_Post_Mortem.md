## Executive Summary

On July 10, 2026, at approximately 09:09 UTC, our security systems detected a series of SQL injection attacks targeting our Socket.IO real‑time communication service. While several attempts were initially blocked, one request succeeded, suggesting that a malicious SQL payload likely reached our database. We have since contained the incident, launched a full investigation, and taken immediate steps to close the gaps that allowed this attack.

## Background

SQL injection is a common but dangerous cyberattack. It works by sending malicious SQL statements through input fields—like search boxes or login forms—to trick the database into revealing or modifying data it shouldn’t. In this case, the attacker targeted the Socket.IO endpoint we use to power live features such as chat, notifications, and real‑time updates.  

We rely on a Web Application Firewall (WAF) to inspect incoming traffic and detect known attack patterns. When the WAF spots something suspicious, it is designed to block the request and alert our security team. However, as this incident shows, detection alone is not enough—the configuration must also enforce a *block* action.

## Incident Timeline

### 2026 July 10 09:09:09 UTC

Two requests arrived from the same internal IP address within the same second. The first was a `POST` to the Socket.IO polling endpoint containing SQL injection patterns. Our detection rule fired immediately, and the request was returned with a `403 Forbidden` status, indicating it was blocked—likely by the WAF or server‑side controls. A second request attempted to upgrade the connection to a WebSocket. It received a `499` status, meaning the client disconnected while the server was still processing the request, possibly due to the detection alert.

### 2026 July 10 09:09:24 UTC

The attacker tried again, this time with a second `POST` polling request carrying another SQL‑injected payload. Again, our detection system identified the attack, and the request was blocked with a `403`. At this point it appeared that our defenses were holding.

### 2026 July 10 09:09:35 UTC

Eleven seconds later, the attacker shifted tactics slightly and sent a `GET` request to the polling endpoint—still containing SQL injection code. This time the response came back as `200 OK`, meaning the request was accepted and processed by the application. The detection rule fired *again* (the same rule that had flagged the earlier attempts), but no action was taken to drop the request. The malicious SQL code reached the database.

## Root Cause Analysis

The attack succeeded because of two intersecting issues:

1. **WAF Misconfiguration** – Our Web Application Firewall was set to “detect only” mode for the SQL injection rule (ID 31101). While it correctly identified every one of the attacker’s attempts, it was not configured to block or redirect the traffic automatically. The field `waf_action=None` in the logs confirms that no active enforcement occurred, even though a threat was recognized.

2. **Application Vulnerability** – The Socket.IO endpoint did not adequately validate or sanitise user‑supplied input. This allowed the SQL‑infused parameter (likely the session ID or transport value) to be passed directly into a database query. SQL injection is preventable with parameterised queries and strict input filtering, and this gap will be addressed immediately.

The attacker’s target was the real‑time communication service, and they exploited a combination of a configuration gap and a code‑level flaw.

## Learnings

This incident has highlighted that detection without timely blocking leaves a dangerous window for adversaries. We are immediately updating our WAF rules to ensure that SQL injection patterns are actively denied, not just recorded. Separately, our engineering team is conducting a thorough code review of all database interactions within the Socket.IO service and implementing parameterised queries across the board. We remain committed to transparency: mistakes are owned and shared openly so our community can trust that we take security seriously.

**Report Date:** 2026-07-11  
**Report Author:** Security Operations Team