# Web-Traffic-Filter-Flask-

🎯 Objective

To build a real‑time, rule‑based HTTP traffic filter that protects web applications from common injection and exploitation attacks. The tool intercepts all incoming requests to a Flask application, applies configurable security rules, and blocks or sanitises any request that matches a malicious pattern. It also implements rate limiting to mitigate brute‑force and denial‑of‑service (DoS) attempts. By logging all blocked requests, the tool provides valuable threat intelligence for security teams, enabling them to identify attack trends and refine their defence strategies.
🧠 How It Works – Technical Overview

The Web Traffic Filter operates as a middleware component within the Flask request‑response cycle. Every incoming request passes through the filter before reaching the intended route handler.
1. Request Interception (@app.before_request)

    The Flask decorator @app.before_request registers a function that executes before any route handler is invoked.

    This function inspects all components of the HTTP request:

        URL path – e.g., /?id=1 or /admin.

        Query parameters – e.g., ?search=<script>.

        Form data (POST) – e.g., username=admin' OR '1'='1.

        JSON body (REST APIs) – e.g., {"email": "test@example.com", "password": "123456"}.

        Request headers (optional) – e.g., User-Agent for bot detection.

2. Pattern Matching & Rule Engine

    The tool maintains a set of regex‑based rules derived from the OWASP ModSecurity Core Rule Set (CRS) and common attack signatures.

    Pattern categories include:

        SQL Injection: (union|select|insert|update|delete|drop|alter)\s+.*\s+(from|into|set|where)

        Cross‑Site Scripting: <script[^>]*>.*?</script>, javascript:, <.*?on\w+=".*?".*?>

        Path Traversal: \.\./\.\./, /etc/passwd, /etc/shadow

        Command Injection: ;\s*(ls|dir|cat|type|echo|net|whoami|id|pwd|cd), \|\s*(ls|dir|cat)

    Each rule is applied to every field in the request. If any field matches any pattern, the request is immediately rejected.

3. Rate Limiting

    Integrates Flask-Limiter to track request frequency per IP address.

    Default limits: 200 requests per day and 50 requests per hour (configurable).

    Prevents brute‑force attacks against login endpoints, API abuse, and application‑level DoS.

    When the limit is exceeded, the filter returns a 429 Too Many Requests status code.

4. Logging & Alerting

    All blocked requests are logged to a structured JSON file (waf_block.log) containing:

        Timestamp.

        Source IP address.

        Request method (GET, POST, etc.).

        Full URL and query string.

        Matched rule (the regex pattern that triggered the block).

    Optionally sends alerts to Slack/Teams for real‑time SOC awareness.

5. Response Handling

    When a request is blocked, the filter returns an HTTP 403 Forbidden status code with a JSON error message:
    json

{"error": "Blocked by security policy", "rule": "SQL injection pattern detected"}

    This provides clear feedback to legitimate clients while obfuscating the exact reason from attackers.

✨ Advanced Features (Real‑World Upgrade)
Feature	Implementation
Dynamic Rule Management	Rules are stored in an external JSON/YAML file, allowing security teams to add, modify, or disable rules without restarting the application.
Whitelist Management	Supports IP‑based and CIDR‑based whitelisting (e.g., internal network IPs) to bypass filtering for trusted sources.
CAPTCHA Integration	For high‑risk endpoints (e.g., /login), the filter can challenge suspicious requests with a CAPTCHA instead of outright blocking, reducing false positives.
Bot Detection	Uses User-Agent analysis and request frequency heuristics to identify and block automated scanners (e.g., sqlmap, nikto, nmap).
Response Inspection	Optionally inspects outbound responses to prevent data leakage (e.g., blocking 500 errors containing stack traces).
ModSecurity Integration	Can be extended to use libmodsecurity (the engine behind ModSecurity) to apply the full OWASP CRS, offering enterprise‑grade protection.
GeoIP Blocking	Blocks requests from high‑risk countries based on a configurable list (e.g., countries with no legitimate business presence).
Alert Deduplication	Prevents repeated alerts for the same attack pattern from the same IP within a configurable time window.
Dashboard Integration	Exports blocked request logs to Elasticsearch or Splunk for visualisation and long‑term threat hunting.
🛠️ Tools & Technologies

    Python 3 – core logic for request inspection and filtering.

    Flask – web framework providing the @app.before_request hook.

    Flask‑Limiter – rate‑limiting extension (uses Redis or memory store).

    Regular Expressions – fast, efficient pattern matching for attack signatures.

    JSON – structured logging for blocked requests.

    requests – optional, for sending Slack alerts.

    YAML/JSON – for external rule configuration.

🔬 Testing & Use Case

Scenario:
A security team deploys a Flask‑based web application for internal use. They want to ensure it is protected against common injection attacks before exposing it to the internet. They enable the Web Traffic Filter on the application.

Process:

    Start the application with the filter enabled:
    bash

python3 waf_pro.py

Penetration test attempt (SQL Injection):

    Attacker sends: GET /?id=1' OR '1'='1

    Filter intercepts and matches the SQL injection pattern (union|select|insert|update|delete|drop|alter) combined with '.

    Action: The filter blocks the request and returns:
    json

{"error": "Blocked by security policy", "rule": "SQL injection detected in parameter 'id'"}

Penetration test attempt (XSS):

    Attacker sends: GET /?q=<script>alert('XSS')</script>

    Filter intercepts and matches the <script> pattern.

    Action: Request blocked with:
    json

{"error": "Blocked by security policy", "rule": "XSS pattern detected in parameter 'q'"}

    Penetration test attempt (Path Traversal):

        Attacker sends: GET /?file=../../etc/passwd

        Filter intercepts and matches \.\./.

        Action: Request blocked.

    Rate limiting test:

        Attacker sends 60 requests per minute to /login.

        Filter intercepts and after 50 requests, returns 429 Too Many Requests.

Outcome:

    All injection attempts are blocked before reaching the application.

    The WAF log file waf_block.log contains detailed entries for each blocked request, providing intelligence on attack patterns.

    The application remains secure and operational for legitimate users.

    The team can refine the rule set based on the logged patterns to reduce false positives.

📁 Output Example (WAF Log Entry)

A typical log entry contains:

    Timestamp – Date and time of the block.

    Client IP – Source address of the attacker.

    Method – HTTP method (e.g., GET, POST).

    URL – Full request URL with query parameters.

    Matched Rule – The regex pattern that triggered the block (e.g., SQL injection pattern).

    Blocked Parameter – The specific field (e.g., id) that contained the malicious payload.

    Response Status – 403 Forbidden.

📝 Conclusion

The Web Traffic Filter (Flask) is a powerful, lightweight Web Application Firewall that provides immediate protection against the most common web application attacks—SQL injection, XSS, path traversal, and command injection. By intercepting requests at the middleware layer, it ensures that malicious payloads never reach application logic, reducing the risk of data breaches and application compromise. Its flexible rule engine, rate‑limiting capabilities, and structured logging make it an ideal solution for securing Flask applications in both development and production environments. During testing, it successfully blocked all injection attempts while allowing legitimate traffic to pass through, demonstrating its effectiveness as a first line of defence. This tool highlights the importance of defence‑in‑depth and provides a practical, deployable security control for organisations of all sizes.
