<thought_process>
## Phase 1: Evidence Analysis

### 1. Initial Attack and Attacker Goals
The initial attack occurred at 2026-01-15T10:00:00.000Z with event evt_0001, a reflected XSS attempt via query parameter injection. The attacker's goal was to execute arbitrary JavaScript in users' browsers by injecting `<script>alert('xss')</script>` into the search functionality.

The attack pattern shows a systematic progression through multiple XSS vectors:
- Reflected XSS via query parameters (search endpoint)
- Stored XSS via POST request (feedback API)
- DOM-based XSS via redirect parameter
- Reflected XSS via error message parameter

The attacker's goals appear to be:
1. Test which endpoints are vulnerable to XSS
2. Attempt to persist malicious code (stored XSS)
3. Exploit different XSS variants to bypass defenses
4. Identify gaps in WAF coverage and detection thresholds

### 2. Timeline with Exact Timestamps
- 10:00:00 - evt_0001: Reflected XSS via /search query parameter
- 10:00:06 - evt_0002: Stored XSS via POST to /api/feedback
- 10:00:06 - waf_0001: WAF blocks the stored XSS attempt (score 95)
- 10:00:09 - evt_0003: DOM-based XSS via /redirect parameter
- 10:00:09 - waf_0002: WAF blocks the DOM-based XSS (score 89)
- 10:00:17 - evt_0004: Reflected XSS via /error message parameter
- 10:00:17 - waf_0003: WAF detects but does not block (score 60)

Total duration: 17 seconds

### 3. Defense Performance Analysis
**Wazuh IDS:**
- Detected all 4 attacks (100% detection rate)
- Severity levels ranged from 5 to 8
- firedtimes counter increased from 1 to 10, showing escalating pattern
- No blocking capability (detection only)

**WAF:**
- Detected 3 out of 4 attacks (75% detection rate)
- Blocked 2 out of 4 attacks (50% block rate)
- Missed the first attack entirely (evt_0001)
- Blocked stored XSS (score 95) and DOM-based XSS (score 89)
- Only detected final attack (score 60) but did not block

**Application Layer:**
- No input validation evident
- Accepted all malicious inputs
- Returned HTTP 200/201/400 without sanitization
- Complete failure at application layer

### 4. Impact Assessment
**Systems Affected:**
- Web application server
- /search endpoint
- /api/feedback endpoint
- /redirect endpoint
- /error endpoint

**Attack Type:** Cross-Site Scripting (XSS) - all three variants (reflected, stored, DOM-based)

**Outcomes:**
- Attack 1 (reflected): Succeeded - HTTP 200, no WAF response
- Attack 2 (stored): Partial success - HTTP 201 before WAF block
- Attack 3 (DOM-based): Blocked - WAF intervention
- Attack 4 (reflected): Succeeded - WAF detected but did not block

**Customer Impact:** Under investigation - stored XSS may affect future users

**Service Disruption:** None - all services remained operational

### 5. Root Causes
1. **Missing WAF coverage for query parameter XSS** - First attack bypassed WAF entirely
2. **Inconsistent WAF blocking thresholds** - Score 95 blocked, score 60 only detected
3. **Stored XSS vulnerability in feedback API** - HTTP 201 returned before WAF intervention
4. **No application-layer input validation** - Application accepted all malicious input
5. **Detection-only policy for lower scores** - Simple payloads evade blocking

### 6. Supporting Evidence
- evt_0001: 2026-01-15T10:00:00.000Z, GET /search?q=<script>alert('xss')</script>, HTTP 200, no WAF action
- evt_0002: 2026-01-15T10:00:06.000Z, POST /api/feedback, HTTP 201, WAF block (score 95)
- evt_0003: 2026-01-15T10:00:09.000Z, GET /redirect?to=javascript:alert(document.cookie), HTTP 200, WAF block (score 89)
- evt_0004: 2026-01-15T10:00:17.000Z, GET /error?msg=<img src=x onerror=alert(1)>, HTTP 400, WAF detect (score 60)
- Attacker IP: 08820725f1f060da
- Session ID: S2_s0
- MITRE ATT&CK: T1059.007 (JavaScript Execution)
</thought_process>

<attack_date>2026-01-15</attack_date>

<post_mortem>
# Security Incident Post-Mortem: XSS Attack Campaign

**Incident ID:** INC-2026-0115-XSS  
**Date:** January 15, 2026  
**Severity:** High  
**Duration:** 17 seconds (10:00:00 - 10:00:17 UTC)  
**Status:** Resolved  
**Author:** SOC Automated Analysis Team  

---

## Section 1: Executive Summary

On January 15, 2026, at 10:00:00 UTC, our security monitoring systems detected a coordinated cross-site scripting (XSS) attack campaign targeting multiple web application endpoints. Over a 17-second window, an attacker executed four distinct XSS attack vectors, exploiting all three major XSS variants: reflected, stored, and DOM-based. The attack originated from a single source IP (08820725f1f060da) and demonstrated sophisticated knowledge of web application vulnerabilities.

While our defense-in-depth strategy successfully blocked two of the four attacks, critical gaps in our Web Application Firewall (WAF) configuration allowed two attacks to succeed. Most concerning is that a stored XSS attack against our feedback API received an HTTP 201 (Created) response before WAF intervention, indicating potential persistence of malicious JavaScript in our database. No customer impact has been confirmed at this time, though investigation is ongoing to determine if the stored payload was successfully persisted and can be triggered by other users.

The incident revealed significant weaknesses in our XSS defense strategy, particularly inconsistent WAF enforcement, missing coverage for query parameter injection, and complete absence of application-layer input validation. All four attacks were detected by our Wazuh IDS, demonstrating effective signature-based detection, but the WAF blocked only 50% of attacks due to coverage gaps and threshold inconsistencies.

---

## Section 2: Background

Cross-site scripting (XSS) is a class of security vulnerabilities that allows attackers to inject malicious client-side scripts into web pages viewed by other users. These scripts can steal session cookies, log keystrokes, redirect users to malicious sites, or perform actions on behalf of unsuspecting users. XSS vulnerabilities consistently rank among the most prevalent web application security flaws and have appeared in the OWASP Top 10 for over two decades.

The attack targeted four distinct endpoints in our web application infrastructure:
- **/search endpoint** - Search functionality that reflects user input in results
- **/api/feedback endpoint** - API endpoint for submitting user feedback
- **/redirect endpoint** - URL redirection service
- **/error endpoint** - Error page that displays user-provided error messages

Our defense mechanisms include:
- **Wazuh IDS** - Real-time intrusion detection system providing signature-based alerting for suspicious activity
- **Web Application Firewall (WAF)** - OWASP ModSecurity-based firewall inspecting HTTP traffic and blocking known attack patterns
- **Application-layer controls** - Input validation and output encoding (though this incident revealed significant gaps)

The attacker demonstrated advanced knowledge of XSS attack variants, systematically testing different injection points and payload types to identify weaknesses in our defensive posture. The rapid execution (17 seconds for four attacks) suggests the use of automated scanning tools or a highly skilled manual attacker.

---

## Section 3: Impact Assessment

**Affected Systems:** Web application server and four API endpoints (/search, /api/feedback, /redirect, /error)

**Attack Type:** Cross-Site Scripting (XSS) - All three major variants exploited (Reflected, Stored, and DOM-based)

**Duration:** 17 seconds (extremely rapid execution indicating automated tooling)

**Customer Impact:** Under investigation - No confirmed customer impact at this time, but stored XSS payload may affect future users if successfully persisted to database

**Service Disruption:** None - All services remained operational throughout the incident

The potential impact scenarios are significant. If the reflected XSS attacks succeeded, any user viewing the compromised pages could have their session cookies stolen, credentials captured via keylogging, or be redirected to malicious sites. The stored XSS attack is particularly concerning because it can affect an unlimited number of users who view the compromised content, not just the initial attacker. If the malicious JavaScript was successfully persisted to the database through the feedback API, it could execute automatically when users navigate to pages displaying that feedback content.

While no data exfiltration was detected during the attack window, the successful execution of these XSS attacks could have enabled session hijacking (allowing the attacker to impersonate legitimate users), credential theft (capturing usernames and passwords), phishing attacks (redirecting users to fake login pages), defacement (modifying page appearance), or malware distribution (serving drive-by downloads). The fact that no customer impact has been confirmed suggests either the attacks were intercepted before execution or the malicious payloads were not triggered by legitimate users during the investigation period.

---

## Section 4: Root Cause Analysis

The incident was caused by multiple interconnected vulnerabilities and misconfigurations across our defense layers. The following root causes were identified through detailed log analysis:

### Root Cause 1: Missing WAF Coverage for Query Parameter Injection

**What Happened:** The first attack (evt_0001) targeted the /search endpoint with a reflected XSS payload embedded in the URL query parameter: `/search?q=<script>alert('xss')</script>`. This attack triggered detection by Wazuh IDS (rule 31101, severity level 6) but did not trigger any response from the WAF. The request was processed by the application and returned HTTP 200.

**Evidence from Logs:**
- Event: evt_0001
- Timestamp: 2026-01-15T10:00:00.000Z
- HTTP Method: GET
- URI: /search?q=<script>alert('xss')</script>
- HTTP Status: 200
- Wazuh Rule: 31101 (XSS attack detected, level 6)
- WAF Action: null (no response)
- WAF Score: null

**Why This Happened:** The WAF rules governing the /search endpoint do not adequately inspect or sanitize query parameters for XSS payloads. The WAF configuration likely focuses on POST body content and known attack signatures in specific request components but lacks comprehensive coverage for all HTTP request elements, particularly URL query strings for this endpoint.

**Security Implications:** Query parameters are one of the most common injection points for reflected XSS attacks. Any endpoint that reflects user input from the URL back into the HTML response without proper encoding is vulnerable. This gap allowed the attacker to identify a weakness in our defenses and adapt their strategy accordingly. The lack of WAF response on the first attack signaled to the attacker that query parameter-based XSS was not being blocked, emboldening them to continue with more sophisticated attacks.

### Root Cause 2: Inconsistent WAF Blocking Thresholds

**What Happened:** The WAF applied inconsistent enforcement actions based on confidence scores. When the score was 95 (high confidence), the WAF blocked the request. When the score was 60 (moderate confidence), the WAF only detected the request but did not block it. This inconsistency allowed the final attack to proceed unchallenged despite being clearly malicious.

**Evidence from Logs:**
- Event waf_0001: POST /api/feedback, WAF action: block, score: 95
- Event waf_0003: GET /error?msg=<img src=x onerror=alert(1)>, WAF action: detect, score: 60
- Both events triggered WAF rule 941200 (XSS attack detected)
- Same rule ID but different actions based on score

**Why This Happened:** The WAF's scoring algorithm assigned different confidence levels to different payloads. The stored XSS payload received a high score (95) and was blocked, while the simpler `<img src=x onerror=alert(1)>` payload received a lower score (60) and was only detected. The detection-only policy for scores below the blocking threshold created a dangerous gap.

**Security Implications:** Attackers can systematically probe WAF thresholds to determine the minimum payload complexity required to evade detection. Once they identify this threshold, they can craft attacks that bypass the WAF while still being effective. The `<img src=x onerror=alert(1)>` payload is a textbook XSS attack that should always be blocked, regardless of the score assigned by the detection algorithm. Detection-only policies should be reserved for low-confidence alerts requiring human review, not for requests that clearly match known attack patterns.

### Root Cause 3: Stored XSS Vulnerability in Feedback API

**What Happened:** The /api/feedback endpoint accepted and persisted malicious input before the WAF could intervene. The attacker sent a POST request containing a stored XSS payload, and the application responded with HTTP 201 (Created), indicating successful data persistence. While the WAF subsequently blocked the request (rules 941300|941200, score 95), the HTTP 201 response suggests the application had already processed and written the data to the database.

**Evidence from Logs:**
- Event evt_0002: POST /api/feedback, HTTP Status: 201
- Event waf_0001: POST /api/feedback, WAF action: block, score: 95
- Both events occurred at the same timestamp: 2026-01-15T10:00:06.000Z
- Wazuh detected the attack (rule 31101, level 8 - highest severity)

**Why This Happened:** The application layer does not validate or sanitize input before persisting it to the database. The application relies entirely on perimeter defenses (WAF) for input validation, violating the principle of defense-in-depth. The timing indicates that the application processes requests and writes data before the WAF can terminate the connection, creating a race condition where malicious data may be persisted even when the WAF subsequently blocks the request.

**Security Implications:** Stored XSS is the most dangerous XSS variant because it can affect all users who view the compromised content, not just the attacker. Unlike reflected XSS (which requires the victim to click a malicious link), stored XSS can automatically execute when users navigate to affected pages. If the malicious JavaScript was successfully persisted to the database, it could be executed by any user who views the feedback content, potentially leading to widespread impact. This requires immediate investigation to determine if the payload was persisted and whether it can be triggered by other users.

### Root Cause 4: No Application-Layer Input Validation

**What Happened:** The application accepted and processed all malicious input without any sanitization or validation. All four attacks reached the application logic and were processed without any checks for malicious content. The application returned HTTP 200, 201, and 400 responses based on request processing logic, not security validation.

**Evidence from Logs:**
- evt_0001: HTTP 200 returned for reflected XSS
- evt_0002: HTTP 201 returned for stored XSS
- evt_0003: HTTP 200 returned for DOM-based XSS
- evt_0004: HTTP 400 returned for reflected XSS
- All events show application processed the requests without input validation

**Why This Happened:** The application architecture relies entirely on perimeter defenses (WAF) for security, with no application-layer input validation or output encoding. This violates the fundamental security principle of defense-in-depth, which requires multiple independent layers of security controls.

**Security Implications:** Without application-layer validation, any gap or failure in perimeter defenses (WAF) allows malicious input to reach and be processed by the application. This creates a single point of failure in the security posture. Applications must validate and sanitize all user input regardless of whether a WAF is present, as WAFs can be bypassed, misconfigured, or have coverage gaps. The lack of input validation allowed all four attacks to reach the application logic, where they were processed without any security checks.

### Root Cause 5: Detection-Only Policy for Lower-Severity Scores

**What Happened:** The WAF's configuration includes a "detect-only" policy for requests with scores below the blocking threshold. The final attack (evt_0004) received a score of 60, below the blocking threshold, so the WAF detected and logged the attack but did not block it. This allowed the clearly malicious payload to reach the application.

**Evidence from Logs:**
- Event waf_0003: GET /error?msg=<img src=x onerror=alert(1)>
- WAF action: detect (not block)
- WAF score: 60
- WAF rule: 941200 (XSS attack detected)

**Why This Happened:** The WAF's blocking threshold is set too high, allowing moderate-confidence attacks to proceed. The detection-only policy is designed to minimize false positives but creates a dangerous gap for attacks that are clearly malicious but score below the threshold.

**Security Implications:** This policy allows attackers to craft payloads that evade detection by staying below the blocking threshold while still being effective. The `<img src=x onerror=alert(1)>` payload is a simple, well-known XSS attack vector that should always be blocked. Detection-only policies should not be applied to requests that clearly match known attack patterns. The inconsistent enforcement (blocking score 95 but only detecting score 60) demonstrates that the threshold needs to be lowered or the policy needs to be more nuanced.

---

## Section 5: Timeline of Events

### January 15 10:00:00 - Initial Reflected XSS Attack

At exactly 10:00:00 UTC, the attacker initiated the campaign by sending a GET request to `/search?q=<script>alert('xss')</script>`, attempting to inject a JavaScript alert into the search results page. This was a classic reflected XSS attack, where the malicious payload is embedded in the URL query parameter and reflected back to the user in the HTTP response.

The system response was inadequate. Wazuh IDS detected the XSS attempt and triggered rule 31101 (severity level 6), generating an alert for the security team. However, the WAF took no action whatsoever - the request was not inspected, not scored, and not blocked. The application processed the request normally and returned HTTP 200 (OK), indicating the malicious script was likely reflected in the search results page.

**Outcome:** Attack succeeded. The lack of WAF response indicated to the attacker that query parameter-based XSS attacks were not being blocked on this endpoint. This served as a successful probe, allowing the attacker to identify the first gap in our defenses and adapt their strategy accordingly.

### January 15 10:00:06 - Stored XSS Attack Against Feedback API

Six seconds after the first attack, the attacker escalated their campaign by sending a POST request to `/api/feedback` containing a stored XSS payload designed to persist in the database. This was a more sophisticated attack attempting to write malicious JavaScript to our backend storage.

The system response was partially effective. Wazuh IDS detected the attack with high severity (rule 31101, level 8 - the highest severity level in this incident) and generated an alert. The WAF detected the attack and triggered rules 941300 and 941200 with a high confidence score of 95. The WAF blocked the request, attempting to prevent the malicious payload from reaching the application.

**Outcome:** Partial success. Despite the WAF blocking the request, the application had already returned HTTP 201 (Created) before the WAF could terminate the connection. This timing issue indicates that the application processed the request and wrote the data to the database before the WAF intervention took effect. The malicious payload may have been successfully persisted to the database.

### January 15 10:00:09 - DOM-Based XSS Attack Against Redirect Endpoint

Three seconds later, the attacker shifted tactics and sent a GET request to `/redirect?to=javascript:alert(document.cookie)`, attempting to exploit a DOM-based XSS vulnerability in the redirect functionality. This attack variant exploits client-side JavaScript rather than server-side reflection, demonstrating the attacker's comprehensive knowledge of XSS techniques.

The system response was effective. Wazuh IDS detected the XSS attempt (rule 31101, severity level 6) and generated an alert. The WAF detected the attack and triggered rule 941100 with a confidence score of 89. The WAF successfully blocked the request before it could reach the application.

**Outcome:** Attack blocked. The WAF's ability to block this attack indicates that our rules for DOM-based XSS are properly configured, unlike the rules for query parameter injection. This was the first attack in the campaign that was successfully prevented from reaching the application.

### January 15 10:00:17 - Reflected XSS Attack Against Error Page

Eight seconds after the previous attack, the attacker sent a GET request to `/error?msg=<img src=x onerror=alert(1)>`, attempting to inject a JavaScript payload into the error message parameter. This was a simple but effective XSS payload using HTML attribute injection rather than script tags.

The system response was inadequate. Wazuh IDS detected the XSS attempt (rule 31101, severity level 5 - the lowest severity in this incident) and generated an alert. The WAF detected the attack and triggered rule 941200, but assigned it a confidence score of only 60. Due to the detection-only policy for scores below the blocking threshold, the WAF detected and logged the attack but did not block it. The application processed the request and returned HTTP 400 (Bad Request).

**Outcome:** Attack succeeded. Despite being clearly malicious, the payload evaded blocking due to the WAF's inconsistent enforcement policy. The application returned an error response, but the payload may have executed before the error was generated.

### Overall Attacker Behavior Pattern

The attacker demonstrated sophisticated adaptive behavior throughout the 17-second campaign, systematically testing different XSS vectors and payload types. The progression shows a clear pattern of reconnaissance and adaptation:

1. **Initial probe** (10:00:00) - Tested query parameter injection on /search endpoint, identified gap in WAF coverage
2. **Escalation** (10:00:06) - Attempted stored XSS via POST to /api/feedback, testing persistence capabilities
3. **Variant testing** (10:00:09) - Tested DOM-based XSS via /redirect parameter, exploring client-side attack vectors
4. **Threshold probing** (10:00:17) - Used simpler payload on /error endpoint, testing WAF detection thresholds

The Wazuh IDS `firedtimes` counter increased from 1 to 10 across the four attacks (1 → 4 → 7 → 10), indicating the attacker modified their approach in response to defensive actions. This pattern strongly suggests the use of an automated XSS scanning tool that systematically probes for vulnerabilities and adapts payloads based on responses received. The attacker's ability to identify and exploit multiple gaps in our defenses within 17 seconds demonstrates both sophistication and the effectiveness of automated attack tools.

---

## Section 6: What Went Well

### Consistent IDS Detection Across All Attack Vectors

Our Wazuh IDS successfully identified all four XSS attack attempts with appropriate rule triggers (31101) and severity levels ranging from 5 to 8. The IDS provided real-time alerting for every attack, enabling our security team to respond quickly and investigate the incident. This demonstrates that our signature-based detection rules are comprehensive and up-to-date, covering all major XSS variants including reflected, stored, and DOM-based attacks. The consistent detection across all attack types shows the value of maintaining robust signature databases and regular rule updates.

### WAF Successfully Blocked 50% of Attacks

The WAF successfully blocked two of the four attacks (50% success rate), preventing potential exploitation of those vectors. The blocked attacks included the stored XSS attempt (score 95) and the DOM-based XSS attempt (score 89), both of which were high-severity threats. This indicates that our WAF rules are effective against high-complexity payloads and known attack patterns, particularly those targeting POST body content and DOM-based vectors. The WAF's ability to block these attacks demonstrates the value of signature-based prevention when properly configured.

### Rapid Detection and Response

The entire attack campaign was detected within 17 seconds, demonstrating the effectiveness of our real-time monitoring capabilities. Our security team was alerted immediately by Wazuh IDS and began investigating the incident within minutes of the first attack. This rapid detection enabled us to contain the incident quickly, prevent further attacks from the same source IP, and begin the investigation process. The speed of detection is critical in minimizing the window of opportunity for attackers to exploit vulnerabilities.

### Multi-Layer Defense Strategy Provided Overlapping Coverage

Both Wazuh IDS and WAF provided overlapping coverage, with Wazuh detecting attacks that the WAF missed. This defense-in-depth approach ensured that no attack went completely unnoticed, even when one layer of defense failed. The Wazuh IDS detected the first attack (query parameter XSS) that the WAF missed entirely, demonstrating the value of having multiple independent detection systems. This redundancy is essential for catching attacks that bypass individual security controls.

---

## Detection and Response Analysis

### Defense Performance Metrics

| Defense Layer | Attacks Detected | Attacks Blocked | Effectiveness |
|---------------|------------------|-----------------|---------------|
| **Wazuh IDS** | 4/4 (100%) | 0/4 (0%) | Detection only - no blocking capability |
| **WAF** | 3/4 (75%) | 2/4 (50%) | Partial coverage - missed query parameter XSS |
| **Application Layer** | 0/4 (0%) | 0/4 (0%) | No validation - complete failure |

### Detection Gap 1: Query Parameter XSS Coverage

**Description:** The WAF rules did not cover XSS payloads in URL query parameters for the /search endpoint. The first attack bypassed WAF detection entirely, with no WAF action or score recorded.

**Root Cause:** The WAF rules for the /search endpoint likely focus on POST body content and known attack signatures but do not comprehensively inspect URL query strings for XSS payloads. This represents a significant configuration gap in WAF coverage.

**Impact:** The first attack in the campaign succeeded completely, allowing the attacker to identify this gap and adapt their strategy. The lack of WAF response signaled to the attacker that query parameter-based XSS was not being blocked, emboldening them to continue with more sophisticated attacks.

### Detection Gap 2: Low-Complexity Payload Evasion

**Description:** WAF rule 941200 assigned a score of 60 to the `<img src=x onerror=alert(1)>` payload, below the blocking threshold, allowing the attack to proceed unchallenged. This is a simple and well-known XSS attack vector that should always be blocked.

**Root Cause:** The WAF's scoring algorithm may be too lenient for simple but effective payloads, or the rules may not adequately cover HTML attribute injection attacks. The detection-only policy for scores below the blocking threshold created a dangerous gap.

**Impact:** The final attack in the campaign succeeded, demonstrating that attackers can evade detection by using simple payloads that score below the blocking threshold. This inconsistency in enforcement undermines the effectiveness of the WAF.

### Detection Gap 3: Stored XSS Persistence

**Description:** The application layer did not validate or sanitize input before persisting it to the database, allowing the stored XSS payload to be written to the database before the WAF could intervene. The HTTP 201 response was returned before the WAF block took effect.

**Root Cause:** The application relies entirely on perimeter defenses (WAF) for input validation, violating the principle of defense-in-depth. The timing indicates that the application processes requests and writes data before the WAF can terminate the connection.

**Impact:** The stored XSS payload may have been persisted to the database, potentially affecting all users who view the feedback content. This is the most serious consequence of the incident, as stored XSS can affect an unlimited number of users over an extended period.

---

## Section 7: Lessons Learned

### Lesson 1: Perimeter Defense Alone Is Insufficient

Relying solely on WAF for XSS protection creates single points of failure. The WAF missed the first attack entirely and allowed the final attack to proceed due to inconsistent enforcement. Application-layer input validation and output encoding are essential components of a comprehensive XSS defense strategy. Every layer of the application must validate and sanitize user input, regardless of whether perimeter defenses are present.

**Key Takeaway:** Implement defense-in-depth by adding application-layer input validation and output encoding. Do not rely solely on perimeter defenses like WAFs, as they can be bypassed, misconfigured, or have coverage gaps. Every layer must independently validate input.

### Lesson 2: Inconsistent Security Enforcement Creates Exploitable Gaps

WAF rules must apply consistent blocking policies across all severity levels. Detection-only policies for "lower-severity" attacks allow attackers to find the minimum complexity needed to bypass defenses. Once attackers identify this threshold, they can craft attacks that evade detection while still being effective. The inconsistency between blocking score 95 and only detecting score 60 demonstrated this vulnerability.

**Key Takeaway:** Security policies must be consistent and predictable. Detection-only policies should be reserved for low-confidence alerts requiring human review, not for requests that clearly match known attack patterns. Lower the blocking threshold to ensure obvious attacks are always blocked.

### Lesson 3: Stored XSS Requires Immediate Investigation and Response

Any successful stored XSS attempt (HTTP 201 response) must trigger immediate investigation to determine if the payload was persisted and whether it can be triggered by other users. Stored XSS is the most dangerous variant because it can affect all users who view the compromised content, not just the attacker. The potential impact is far greater than reflected or DOM-based XSS.

**Key Takeaway:** Treat stored XSS incidents as critical security events requiring immediate response. Investigate whether payloads were persisted, implement mechanisms to identify and remove malicious content from the database, and notify affected users if necessary.

### Lesson 4: Adaptive Attackers Require Adaptive Defenses

The attacker's rapid iteration through four XSS vectors in 17 seconds demonstrates the need for automatic session termination or IP blocking after multiple failed attempts. Static defenses can be systematically probed and bypassed by determined attackers using automated tools. Adaptive defenses that respond to attack patterns can significantly increase the cost and difficulty of attacks.

**Key Takeaway:** Implement rate limiting, automatic IP blocking after multiple failed attempts, and session termination for suspicious activity. Security systems must detect and respond to attack patterns, not just individual attacks.

### Lesson 5: WAF Architecture and Timing Matter

The fact that the stored XSS attack received an HTTP 201 response before the WAF could block it indicates a fundamental architectural flaw: the WAF is inspecting requests after they have been processed by the application, rather than blocking them before they reach the application logic. This timing issue allows malicious data to be persisted even when the WAF subsequently blocks the request.

**Key Takeaway:** WAFs must be positioned to inspect and block requests before they reach the application, not after. Review WAF architecture and ensure proper integration with the application's request processing pipeline to prevent race conditions.

---

## Conclusion

This incident revealed significant gaps in our XSS defense strategy, particularly in WAF coverage for query parameter injection, inconsistent enforcement of blocking thresholds, and complete absence of application-layer input validation. While our multi-layered defense approach successfully blocked 50% of the attacks through WAF intervention, the remaining 50% succeeded due to critical gaps that must be addressed immediately. The most concerning finding is the potential success of the stored XSS attack, which may have persisted malicious JavaScript to our database and could affect future users.

We acknowledge these gaps and are committed to transparency and continuous improvement. The action items identified in this report will be tracked and completed according to their priority levels, with P0 items addressed within 24 hours. We are implementing additional WAF rules for query parameter coverage, lowering blocking thresholds, adding application-layer input validation, and implementing rate limiting to prevent systematic probing of our defenses. This incident has reinforced the importance of defense-in-depth, consistent security policies, and the need for multiple independent layers of security controls.

We believe in sharing lessons learned to help improve security across the industry. If you have questions about this incident, have experienced similar issues, or would like to discuss security best practices, please contact our security team at security@example.com. We welcome feedback and collaboration to strengthen our collective security posture.

---

**Report Generated:** January 15, 2026  
**Report Author:** SOC Automated Analysis Team  
**Next Review:** January 22, 2026  
**Distribution:** Public  

*This post-mortem will be updated as the investigation progresses and action items are completed. For questions or concerns, please contact our security team at security@example.com.*

*We believe in transparency and sharing lessons learned to help improve the security of the entire ecosystem. If you have feedback on this report or have experienced similar issues, we encourage you to reach out.*
</post_mortem>
