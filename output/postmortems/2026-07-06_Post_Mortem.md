## Executive Summary

On July 6, 2026, our security systems detected a coordinated automated attack targeting our web application. The attacker performed active reconnaissance, attempted SQL injection and cross-site scripting (XSS) exploits, and launched a wave of login attempts. Our Web Application Firewall (WAF) and intrusion detection system (Wazuh) successfully identified and blocked all malicious requests, preventing any data breach or unauthorized access. However, the attack temporarily disrupted the login service, producing error responses that may have affected a small number of legitimate users. This report details the incident timeline, root causes, and the improvements we are implementing to strengthen our defenses.

## Background

The attacker used techniques common in web application attacks: SQL injection and cross-site scripting. In a SQL injection attack, an attacker inserts malicious database commands into input fields to trick the application into revealing or manipulating private data. Cross-site scripting works by injecting a script into a webpage that can steal user cookies or redirect browsers. Both attacks rely on the application failing to properly sanitize user input. In this incident, the attacker targeted our product search API and user login page – two entry points that accept end-user data. We protect these endpoints with a Web Application Firewall that inspects every request and a security monitoring platform (Wazuh) that analyzes server logs for suspicious patterns. These defenses work together to detect and block attacks in real time.

## Incident Timeline

**2026 July 06 08:05:36 UTC**

The first sign of trouble appeared in our logs: a request to the product search endpoint containing the SQL injection fragment `lol' OR 1=1--`. This classic technique tries to force the database to return all records instead of only the ones matching a search term. The WAF immediately recognised the pattern and returned a `403 Forbidden` response, blocking the query from reaching the application backend. Our Wazuh security monitoring system flagged the event as a SQL injection attempt (rule 31101) and created an alert.

**2026 July 06 08:05:45 UTC**

Only nine seconds later, the same attacker (IP address 172.20.0.1) tried a different attack vector: a cross-site scripting payload in the search field. The URL contained `<script>alert(1)</script>`, a simple JavaScript snippet designed to test whether the application would reflect the script back to a user’s browser. Again the WAF rejected the request with a `403` status, and Wazuh recorded the XSS attempt. At this point, the attacker had confirmed that the search endpoint was defended.

**2026 July 06 08:11:58 UTC**

The attacker escalated the engagement. In a single second, our WAF logged eight requests from the same internal source IP (`localhost`, indicating the requests arrived through our internal load balancing layer). The sequence began with a `GET /` scan of the application root, which returned a `502 Bad Gateway` error – likely because the backend was temporarily overwhelmed by the sudden traffic. The attacker then sent six consecutive `POST` requests to the user login endpoint. All six received `502` responses, suggesting the login service was unable to process requests under the load. The attacker also repeated the earlier SQL injection and XSS attempts, which were again blocked with `403`. A final login request resulted in a `400 Bad Request`, possibly a malformed payload or a different attack variant. Throughout this burst, the WAF categorised the activity as a “WebScan” (MITRE T1595.001 – Active Scanning), alerting our security team to an ongoing probe.

## Root Cause Analysis

The attack succeeded in reaching the application only as far as our defensive perimeter; the actual injection and scripting attempts were blocked. However, the incident exposed two underlying issues. First, the application endpoints lacked sufficient input validation. The product search and login fields accepted raw user input, which would have been executed by the database or browser if not for the WAF. Second, the `POST /rest/user/login` endpoint became unavailable during the scan, returning `502` errors. This indicates that the server could not handle the request volume or that the WAF’s detection mode placed an unexpected load on the backend. The root cause is twofold: missing secure coding practices for input handling, and insufficient capacity or error handling under attack conditions. The specific vulnerabilities that the attacker targeted – SQL injection and XSS – are well-known flaws that should have been prevented at the code level. Our defensive tools compensated, but relying solely on external controls is not a durable solution.

## Learnings

This incident validates that our security monitoring and web application firewall can detect and stop active attacks. However, we identified a gap in input sanitization at the application layer, which we are now addressing through a comprehensive code review of all input points. We are also improving the resilience of the login service by adding rate limiting and more robust error handling to prevent `502` outages during scans. Additionally, we will tighten WAF rule coverage to ensure specific attack signatures are matched rather than relying on generic “WebScan” detection. We remain committed to transparency and will continue to share what we learn from every incident to build a stronger, safer platform.

Report Date: 2026-07-12  
Report Author: Security Operations Team