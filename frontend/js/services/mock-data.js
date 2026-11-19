/*
 * Static fixture data used when LogAnalyzer.config.USE_MOCK is true.
 * Shaped to match the real backend responses documented in api.js.
 */
(function () {
  window.LogAnalyzer = window.LogAnalyzer || {};
  window.LogAnalyzer.services = window.LogAnalyzer.services || {};

  var SUMMARY = {
    total_events: 18406,
    total_threats: 12,
    critical_threats: 2,
    unique_ips: 11
  };

  var STATS = {
    severity_counts: {
      CRITICAL: 2,
      HIGH: 6,
      MEDIUM: 4,
      LOW: 0
    },
    top_risk_ips: [
      { ip: "203.0.113.45", risk_score: 97, threat_count: 2 },
      { ip: "45.33.32.156", risk_score: 57, threat_count: 1 },
      { ip: "185.220.101.9", risk_score: 48, threat_count: 1 },
      { ip: "198.51.100.7", risk_score: 31, threat_count: 1 },
      { ip: "103.208.220.12", risk_score: 29, threat_count: 1 }
    ],
    recent_summaries: [
      {
        id: 2,
        total_events: 18406,
        total_threats: 12,
        critical_threats: 2,
        unique_ips: 11,
        created_at: "2026-09-27 03:15:00"
      },
      {
        id: 1,
        total_events: 16988,
        total_threats: 9,
        critical_threats: 1,
        unique_ips: 7,
        created_at: "2026-09-26 22:40:00"
      }
    ]
  };

  var THREATS = [
    {
      id: 1,
      type: "SSH_BRUTE_FORCE_SUCCESS",
      ip: "203.0.113.45",
      severity: "CRITICAL",
      badge: "red",
      title: "Successful Brute-Force Login",
      details: "Successful SSH login for 'root' from 203.0.113.45 within 60s of 37 failed attempts",
      timestamp: "2026-09-27 02:14:51",
      risk_score: 97,
      risk_factors: [
        { factor: "rule:SSH_BRUTE_FORCE_SUCCESS", points: 45, detail: "Successful Brute-Force Login detected (SSH_BRUTE_FORCE_SUCCESS)" },
        { factor: "rule:SSH_BRUTE_FORCE", points: 35, detail: "SSH Brute-Force Attack detected (SSH_BRUTE_FORCE)" },
        { factor: "failed_logins", points: 25, detail: "37 failed login events (2 pts each, max 25)" },
        { factor: "capped_at_100", points: -5, detail: "raw base 105 exceeds the maximum of 100" },
        { factor: "time_decay", points: -3, detail: "last event 1.0h before the newest event; x0.971 (lambda=0.0289/h)" }
      ]
    },
    {
      id: 2,
      type: "SSH_BRUTE_FORCE",
      ip: "203.0.113.45",
      severity: "HIGH",
      badge: "orange",
      title: "SSH Brute-Force Attack",
      details: "37 failed SSH login attempts from 203.0.113.45 within 60s (threshold: >5); most targeted users: root, admin",
      timestamp: "2026-09-27 02:14:05",
      risk_score: 97,
      risk_factors: [
        { factor: "rule:SSH_BRUTE_FORCE_SUCCESS", points: 45, detail: "Successful Brute-Force Login detected (SSH_BRUTE_FORCE_SUCCESS)" },
        { factor: "rule:SSH_BRUTE_FORCE", points: 35, detail: "SSH Brute-Force Attack detected (SSH_BRUTE_FORCE)" },
        { factor: "failed_logins", points: 25, detail: "37 failed login events (2 pts each, max 25)" },
        { factor: "capped_at_100", points: -5, detail: "raw base 105 exceeds the maximum of 100" },
        { factor: "time_decay", points: -3, detail: "last event 1.0h before the newest event; x0.971 (lambda=0.0289/h)" }
      ]
    },
    {
      id: 3,
      type: "SQL_INJECTION",
      ip: "198.51.100.7",
      severity: "HIGH",
      badge: "orange",
      title: "SQL Injection Attempt",
      details: "SQL Injection attempt (matched 'union select') in GET /products?id=1 UNION SELECT [status 403]",
      timestamp: "2026-09-27 01:58:40",
      risk_score: 31,
      risk_factors: [
        { factor: "rule:SQL_INJECTION", points: 30, detail: "SQL Injection Attempt detected (SQL_INJECTION)" },
        { factor: "exploit_requests", points: 2, detail: "2 requests with exploit patterns (1 pt each, max 15)" },
        { factor: "time_decay", points: -1, detail: "last event 1.3h before the newest event; x0.964 (lambda=0.0289/h)" }
      ]
    },
    {
      id: 4,
      type: "DIRECTORY_TRAVERSAL",
      ip: "192.0.2.12",
      severity: "HIGH",
      badge: "orange",
      title: "Directory Traversal Attempt",
      details: "Directory Traversal attempt (matched '../') in GET /../../etc/passwd [status 403]",
      timestamp: "2026-09-27 01:46:12",
      risk_score: 26,
      risk_factors: [
        { factor: "rule:DIRECTORY_TRAVERSAL", points: 25, detail: "Directory Traversal Attempt detected (DIRECTORY_TRAVERSAL)" },
        { factor: "exploit_requests", points: 2, detail: "2 requests with exploit patterns (1 pt each, max 15)" },
        { factor: "time_decay", points: -1, detail: "last event 1.5h before the newest event; x0.958 (lambda=0.0289/h)" }
      ]
    },
    {
      id: 5,
      type: "XSS_ATTEMPT",
      ip: "185.220.101.5",
      severity: "MEDIUM",
      badge: "yellow",
      title: "Cross-Site Scripting Attempt",
      details: "Cross-Site Scripting (XSS) attempt (matched '<script') in GET /comments?msg=<script> [status 200]",
      timestamp: "2026-09-27 01:20:55",
      risk_score: 16,
      risk_factors: [
        { factor: "rule:XSS_ATTEMPT", points: 15, detail: "Cross-Site Scripting Attempt detected (XSS_ATTEMPT)" },
        { factor: "exploit_requests", points: 2, detail: "2 requests with exploit patterns (1 pt each, max 15)" },
        { factor: "time_decay", points: -1, detail: "last event 1.9h before the newest event; x0.947 (lambda=0.0289/h)" }
      ]
    },
    {
      id: 6,
      type: "PORT_SCAN",
      ip: "185.220.101.9",
      severity: "HIGH",
      badge: "orange",
      title: "Port Scan",
      details: "14 distinct destination ports probed from 185.220.101.9 within 60s",
      timestamp: "2026-09-27 02:11:00",
      risk_score: 48,
      risk_factors: [
        { factor: "rule:PORT_SCAN", points: 30, detail: "Port Scan detected (PORT_SCAN)" },
        { factor: "honeypot", points: 20, detail: "targeted honeypot 10.0.0.5" },
        { factor: "time_decay", points: -2, detail: "last event 1.1h before the newest event; x0.970 (lambda=0.0289/h)" }
      ]
    },
    {
      id: 7,
      type: "WEB_DIRECTORY_SCAN",
      ip: "198.51.100.88",
      severity: "MEDIUM",
      badge: "yellow",
      title: "Web Content Scan",
      details: "24 distinct URL paths requested from 198.51.100.88 within 60s (content/scan activity)",
      timestamp: "2026-09-27 02:22:45",
      risk_score: 20,
      risk_factors: [
        { factor: "rule:WEB_DIRECTORY_SCAN", points: 20, detail: "Web Content Scan detected (WEB_DIRECTORY_SCAN)" },
        { factor: "time_decay", points: 0, detail: "last event 0.9h before the newest event; x0.975 (lambda=0.0289/h)" }
      ]
    },
    {
      id: 8,
      type: "TRAFFIC_SPIKE",
      ip: "89.248.165.71",
      severity: "MEDIUM",
      badge: "yellow",
      title: "Traffic Spike / Volumetric Pattern",
      details: "85 HTTP requests in a single minute from 89.248.165.71 (threshold: 60/min)",
      timestamp: "2026-09-27 00:42:10",
      risk_score: 14,
      risk_factors: [
        { factor: "rule:TRAFFIC_SPIKE", points: 15, detail: "Traffic Spike / Volumetric Pattern detected (TRAFFIC_SPIKE)" },
        { factor: "time_decay", points: -1, detail: "last event 2.5h before the newest event; x0.929 (lambda=0.0289/h)" }
      ]
    },
    {
      id: 9,
      type: "OFF_HOUR_ADMIN",
      ip: "192.168.1.105",
      severity: "MEDIUM",
      badge: "yellow",
      title: "Off-Hour Administrative Activity",
      details: "Off-hour successful login for sensitive account 'root' at 03:15 from 192.168.1.105",
      timestamp: "2026-09-27 03:15:00",
      risk_score: 10,
      risk_factors: [
        { factor: "rule:OFF_HOUR_ADMIN", points: 10, detail: "Off-Hour Administrative Activity detected (OFF_HOUR_ADMIN)" }
      ]
    },
    {
      id: 10,
      type: "SSH_BRUTE_FORCE",
      ip: "45.33.32.156",
      severity: "CRITICAL",
      badge: "red",
      title: "SSH Brute-Force Attack",
      details: "18 failed SSH login attempts from 45.33.32.156 within 60s (threshold: >5); most targeted users: admin",
      timestamp: "2026-09-27 01:35:04",
      risk_score: 57,
      risk_factors: [
        { factor: "rule:SSH_BRUTE_FORCE", points: 35, detail: "SSH Brute-Force Attack detected (SSH_BRUTE_FORCE)" },
        { factor: "failed_logins", points: 25, detail: "18 failed login events (2 pts each, max 25)" },
        { factor: "time_decay", points: -3, detail: "last event 1.7h before the newest event; x0.953 (lambda=0.0289/h)" }
      ]
    },
    {
      id: 11,
      type: "SQL_INJECTION",
      ip: "103.208.220.12",
      severity: "HIGH",
      badge: "orange",
      title: "SQL Injection Attempt",
      details: "SQL Injection attempt (matched 'or 1=1') in POST /auth/jwt/login [status 401]",
      timestamp: "2026-09-27 01:15:33",
      risk_score: 29,
      risk_factors: [
        { factor: "rule:SQL_INJECTION", points: 30, detail: "SQL Injection Attempt detected (SQL_INJECTION)" },
        { factor: "exploit_requests", points: 1, detail: "1 request with exploit patterns (1 pt each, max 15)" },
        { factor: "time_decay", points: -2, detail: "last event 2.0h before the newest event; x0.944 (lambda=0.0289/h)" }
      ]
    },
    {
      id: 12,
      type: "DIRECTORY_TRAVERSAL",
      ip: "194.26.29.112",
      severity: "HIGH",
      badge: "orange",
      title: "Directory Traversal Attempt",
      details: "Directory Traversal attempt (matched '/etc/passwd') in GET /cgi-bin/test.sh [status 403]",
      timestamp: "2026-09-27 01:52:18",
      risk_score: 26,
      risk_factors: [
        { factor: "rule:DIRECTORY_TRAVERSAL", points: 25, detail: "Directory Traversal Attempt detected (DIRECTORY_TRAVERSAL)" },
        { factor: "exploit_requests", points: 2, detail: "2 requests with exploit patterns (1 pt each, max 15)" },
        { factor: "time_decay", points: -1, detail: "last event 1.4h before the newest event; x0.961 (lambda=0.0289/h)" }
      ]
    }
  ];

  var EVENTS = [
    { id: 54, timestamp: "Sep 27 02:14:51", ip: "203.0.113.45", user: "root", action: "ssh_login_success", log_type: "auth", raw_line: "Sep 27 02:14:51 web01 sshd[2258]: Accepted password for root from 203.0.113.45 port 52238 ssh2" },
    { id: 53, timestamp: "Sep 27 02:14:39", ip: "203.0.113.45", user: "root", action: "ssh_login_failure", log_type: "auth", raw_line: "Sep 27 02:14:39 web01 sshd[2251]: Failed password for root from 203.0.113.45 port 52231 ssh2" },
    { id: 52, timestamp: "Sep 27 02:14:28", ip: "203.0.113.45", user: "admin", action: "ssh_login_failure", log_type: "auth", raw_line: "Sep 27 02:14:28 web01 sshd[2245]: Failed password for invalid user admin from 203.0.113.45 port 52225 ssh2" },
    { id: 51, timestamp: "Sep 27 02:14:23", ip: "203.0.113.45", user: "admin", action: "ssh_login_failure", log_type: "auth", raw_line: "Sep 27 02:14:23 web01 sshd[2241]: Failed password for admin from 203.0.113.45 port 52222 ssh2" },
    { id: 50, timestamp: "Sep 27 02:14:19", ip: "203.0.113.45", user: "admin", action: "ssh_login_failure", log_type: "auth", raw_line: "Sep 27 02:14:19 web01 sshd[2239]: Failed password for invalid user admin from 203.0.113.45 port 52220 ssh2" },
    { id: 49, timestamp: "Sep 27 02:14:16", ip: "203.0.113.45", user: "admin", action: "ssh_login_failure", log_type: "auth", raw_line: "Sep 27 02:14:16 web01 sshd[2236]: Failed password for invalid user admin from 203.0.113.45 port 52218 ssh2" },
    { id: 48, timestamp: "Sep 27 02:14:12", ip: "203.0.113.45", user: "root", action: "ssh_login_failure", log_type: "auth", raw_line: "Sep 27 02:14:12 web01 sshd[2234]: Failed password for root from 203.0.113.45 port 52216 ssh2" },
    { id: 47, timestamp: "Sep 27 02:14:09", ip: "203.0.113.45", user: "root", action: "ssh_login_failure", log_type: "auth", raw_line: "Sep 27 02:14:09 web01 sshd[2232]: Failed password for root from 203.0.113.45 port 52213 ssh2" },
    { id: 46, timestamp: "Sep 27 02:14:05", ip: "203.0.113.45", user: "root", action: "ssh_login_failure", log_type: "auth", raw_line: "Sep 27 02:14:05 web01 sshd[2231]: Failed password for root from 203.0.113.45 port 52211 ssh2" },

    { id: 45, timestamp: "Sep 27 01:35:04", ip: "45.33.32.156", user: "admin", action: "ssh_login_failure", log_type: "auth", raw_line: "Sep 27 01:35:04 web01 sshd[3106]: Failed password for admin from 45.33.32.156 port 44110 ssh2" },
    { id: 44, timestamp: "Sep 27 01:35:00", ip: "45.33.32.156", user: "admin", action: "ssh_login_failure", log_type: "auth", raw_line: "Sep 27 01:35:00 web01 sshd[3105]: Failed password for admin from 45.33.32.156 port 44108 ssh2" },
    { id: 43, timestamp: "Sep 27 01:34:58", ip: "45.33.32.156", user: "admin", action: "ssh_login_failure", log_type: "auth", raw_line: "Sep 27 01:34:58 web01 sshd[3104]: Failed password for admin from 45.33.32.156 port 44106 ssh2" },
    { id: 42, timestamp: "Sep 27 01:34:53", ip: "45.33.32.156", user: "admin", action: "ssh_login_failure", log_type: "auth", raw_line: "Sep 27 01:34:53 web01 sshd[3103]: Failed password for invalid user admin from 45.33.32.156 port 44104 ssh2" },
    { id: 41, timestamp: "Sep 27 01:34:47", ip: "45.33.32.156", user: "admin", action: "ssh_login_failure", log_type: "auth", raw_line: "Sep 27 01:34:47 web01 sshd[3102]: Failed password for admin from 45.33.32.156 port 44102 ssh2" },
    { id: 40, timestamp: "Sep 27 01:34:40", ip: "45.33.32.156", user: "admin", action: "ssh_login_failure", log_type: "auth", raw_line: "Sep 27 01:34:40 web01 sshd[3101]: Failed password for admin from 45.33.32.156 port 44100 ssh2" },

    { id: 39, timestamp: "Sep 27 03:15:00", ip: "192.168.1.105", user: "root", action: "ssh_login_success", log_type: "auth", raw_line: "Sep 27 03:15:00 web01 sshd[4001]: Accepted password for root from 192.168.1.105 port 55000 ssh2" },

    { id: 38, timestamp: "27/Sep/2026:01:58:40 +0000", ip: "198.51.100.7", user: null, action: "http_request", log_type: "web", raw_line: '198.51.100.7 - - [27/Sep/2026:01:58:40 +0000] "GET /products?id=1%20OR%20%271%27%3D%271 HTTP/1.1" 403 128 "-" "sqlmap/1.7.2"' },
    { id: 37, timestamp: "27/Sep/2026:01:58:33 +0000", ip: "198.51.100.7", user: null, action: "http_request", log_type: "web", raw_line: '198.51.100.7 - - [27/Sep/2026:01:58:33 +0000] "GET /products?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 403 128 "-" "sqlmap/1.7.2"' },
    { id: 36, timestamp: "27/Sep/2026:01:58:20 +0000", ip: "198.51.100.7", user: null, action: "http_request", log_type: "web", raw_line: '198.51.100.7 - - [27/Sep/2026:01:58:20 +0000] "GET /products?id=1 HTTP/1.1" 200 512 "-" "Mozilla/5.0"' },

    { id: 35, timestamp: "27/Sep/2026:01:15:33 +0000", ip: "103.208.220.12", user: null, action: "http_request", log_type: "web", raw_line: '103.208.220.12 - - [27/Sep/2026:01:15:33 +0000] "POST /auth/jwt/login?user=admin%27--%20 HTTP/1.1" 401 256 "-" "sqlmap/1.7.2"' },
    { id: 34, timestamp: "27/Sep/2026:01:15:20 +0000", ip: "103.208.220.12", user: null, action: "http_request", log_type: "web", raw_line: '103.208.220.12 - - [27/Sep/2026:01:15:20 +0000] "POST /auth/jwt/login?user=%27%20OR%20%271%27%3D%271 HTTP/1.1" 401 256 "-" "sqlmap/1.7.2"' },
    { id: 33, timestamp: "27/Sep/2026:01:15:10 +0000", ip: "103.208.220.12", user: null, action: "http_request", log_type: "web", raw_line: '103.208.220.12 - - [27/Sep/2026:01:15:10 +0000] "POST /auth/jwt/login HTTP/1.1" 401 256 "-" "sqlmap/1.7.2"' },

    { id: 32, timestamp: "27/Sep/2026:01:46:12 +0000", ip: "192.0.2.12", user: null, action: "http_request", log_type: "web", raw_line: '192.0.2.12 - - [27/Sep/2026:01:46:12 +0000] "GET /../../etc/passwd HTTP/1.1" 403 128 "-" "curl/8.4.0"' },
    { id: 31, timestamp: "27/Sep/2026:01:46:02 +0000", ip: "192.0.2.12", user: null, action: "http_request", log_type: "web", raw_line: '192.0.2.12 - - [27/Sep/2026:01:46:02 +0000] "GET /download?file=../../../etc/passwd HTTP/1.1" 403 128 "-" "curl/8.4.0"' },
    { id: 30, timestamp: "27/Sep/2026:01:45:50 +0000", ip: "192.0.2.12", user: null, action: "http_request", log_type: "web", raw_line: '192.0.2.12 - - [27/Sep/2026:01:45:50 +0000] "GET /download?file=report.pdf HTTP/1.1" 200 2048 "-" "curl/8.4.0"' },

    { id: 29, timestamp: "27/Sep/2026:01:52:18 +0000", ip: "194.26.29.112", user: null, action: "http_request", log_type: "web", raw_line: '194.26.29.112 - - [27/Sep/2026:01:52:18 +0000] "GET /cgi-bin/test.sh?f=/etc/passwd HTTP/1.1" 403 128 "-" "curl/8.4.0"' },
    { id: 28, timestamp: "27/Sep/2026:01:52:05 +0000", ip: "194.26.29.112", user: null, action: "http_request", log_type: "web", raw_line: '194.26.29.112 - - [27/Sep/2026:01:52:05 +0000] "GET /cgi-bin/../../etc/passwd HTTP/1.1" 403 128 "-" "curl/8.4.0"' },
    { id: 27, timestamp: "27/Sep/2026:01:51:55 +0000", ip: "194.26.29.112", user: null, action: "http_request", log_type: "web", raw_line: '194.26.29.112 - - [27/Sep/2026:01:51:55 +0000] "GET /cgi-bin/test.sh HTTP/1.1" 200 64 "-" "curl/8.4.0"' },

    { id: 26, timestamp: "27/Sep/2026:01:20:55 +0000", ip: "185.220.101.5", user: null, action: "http_request", log_type: "web", raw_line: '185.220.101.5 - - [27/Sep/2026:01:20:55 +0000] "GET /comments?msg=<script>document.cookie</script> HTTP/1.1" 200 512 "-" "Mozilla/5.0"' },
    { id: 25, timestamp: "27/Sep/2026:01:20:44 +0000", ip: "185.220.101.5", user: null, action: "http_request", log_type: "web", raw_line: '185.220.101.5 - - [27/Sep/2026:01:20:44 +0000] "GET /comments?msg=<script>alert(1)</script> HTTP/1.1" 200 512 "-" "Mozilla/5.0"' },
    { id: 24, timestamp: "27/Sep/2026:01:20:30 +0000", ip: "185.220.101.5", user: null, action: "http_request", log_type: "web", raw_line: '185.220.101.5 - - [27/Sep/2026:01:20:30 +0000] "GET /comments HTTP/1.1" 200 512 "-" "Mozilla/5.0"' },

    { id: 23, timestamp: "27/Sep/2026:02:22:45 +0000", ip: "198.51.100.88", user: null, action: "http_request", log_type: "web", raw_line: '198.51.100.88 - - [27/Sep/2026:02:22:45 +0000] "GET /.git/config HTTP/1.1" 404 128 "-" "Mozilla/5.0"' },
    { id: 22, timestamp: "27/Sep/2026:02:22:35 +0000", ip: "198.51.100.88", user: null, action: "http_request", log_type: "web", raw_line: '198.51.100.88 - - [27/Sep/2026:02:22:35 +0000] "GET /manager HTTP/1.1" 404 128 "-" "Mozilla/5.0"' },
    { id: 21, timestamp: "27/Sep/2026:02:22:25 +0000", ip: "198.51.100.88", user: null, action: "http_request", log_type: "web", raw_line: '198.51.100.88 - - [27/Sep/2026:02:22:25 +0000] "GET /phpmyadmin HTTP/1.1" 404 128 "-" "Mozilla/5.0"' },
    { id: 20, timestamp: "27/Sep/2026:02:22:15 +0000", ip: "198.51.100.88", user: null, action: "http_request", log_type: "web", raw_line: '198.51.100.88 - - [27/Sep/2026:02:22:15 +0000] "GET /wp-admin HTTP/1.1" 404 128 "-" "Mozilla/5.0"' },
    { id: 19, timestamp: "27/Sep/2026:02:22:05 +0000", ip: "198.51.100.88", user: null, action: "http_request", log_type: "web", raw_line: '198.51.100.88 - - [27/Sep/2026:02:22:05 +0000] "GET /admin HTTP/1.1" 404 128 "-" "Mozilla/5.0"' },

    { id: 18, timestamp: "27/Sep/2026:00:42:10 +0000", ip: "89.248.165.71", user: null, action: "http_request", log_type: "web", raw_line: '89.248.165.71 - - [27/Sep/2026:00:42:10 +0000] "GET /internal/metrics HTTP/1.1" 200 256 "-" "python-requests/2.31"' },
    { id: 17, timestamp: "27/Sep/2026:00:42:08 +0000", ip: "89.248.165.71", user: null, action: "http_request", log_type: "web", raw_line: '89.248.165.71 - - [27/Sep/2026:00:42:08 +0000] "GET /internal/metrics HTTP/1.1" 200 256 "-" "python-requests/2.31"' },
    { id: 16, timestamp: "27/Sep/2026:00:42:06 +0000", ip: "89.248.165.71", user: null, action: "http_request", log_type: "web", raw_line: '89.248.165.71 - - [27/Sep/2026:00:42:06 +0000] "GET /internal/metrics HTTP/1.1" 200 256 "-" "python-requests/2.31"' },
    { id: 15, timestamp: "27/Sep/2026:00:42:04 +0000", ip: "89.248.165.71", user: null, action: "http_request", log_type: "web", raw_line: '89.248.165.71 - - [27/Sep/2026:00:42:04 +0000] "GET /internal/metrics HTTP/1.1" 200 256 "-" "python-requests/2.31"' },
    { id: 14, timestamp: "27/Sep/2026:00:42:03 +0000", ip: "89.248.165.71", user: null, action: "http_request", log_type: "web", raw_line: '89.248.165.71 - - [27/Sep/2026:00:42:03 +0000] "GET /internal/metrics HTTP/1.1" 200 256 "-" "python-requests/2.31"' },
    { id: 13, timestamp: "27/Sep/2026:00:42:02 +0000", ip: "89.248.165.71", user: null, action: "http_request", log_type: "web", raw_line: '89.248.165.71 - - [27/Sep/2026:00:42:02 +0000] "GET /internal/metrics HTTP/1.1" 200 256 "-" "python-requests/2.31"' },
    { id: 12, timestamp: "27/Sep/2026:00:42:01 +0000", ip: "89.248.165.71", user: null, action: "http_request", log_type: "web", raw_line: '89.248.165.71 - - [27/Sep/2026:00:42:01 +0000] "GET /internal/metrics HTTP/1.1" 200 256 "-" "python-requests/2.31"' },
    { id: 11, timestamp: "27/Sep/2026:00:42:00 +0000", ip: "89.248.165.71", user: null, action: "http_request", log_type: "web", raw_line: '89.248.165.71 - - [27/Sep/2026:00:42:00 +0000] "GET /internal/metrics HTTP/1.1" 200 256 "-" "python-requests/2.31"' },

    { id: 10, timestamp: "Sep 27 02:11:00", ip: "185.220.101.9", user: null, action: "firewall_block", log_type: "syslog", raw_line: "Sep 27 02:11:00 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:11 SRC=185.220.101.9 DST=10.0.0.5 PROTO=TCP SPT=51003 DPT=8080 WINDOW=1024" },
    { id: 9, timestamp: "Sep 27 02:10:55", ip: "185.220.101.9", user: null, action: "firewall_block", log_type: "syslog", raw_line: "Sep 27 02:10:55 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:11 SRC=185.220.101.9 DST=10.0.0.5 PROTO=TCP SPT=51002 DPT=443 WINDOW=1024" },
    { id: 8, timestamp: "Sep 27 02:10:48", ip: "185.220.101.9", user: null, action: "firewall_block", log_type: "syslog", raw_line: "Sep 27 02:10:48 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:11 SRC=185.220.101.9 DST=10.0.0.5 PROTO=TCP SPT=51001 DPT=80 WINDOW=1024" },
    { id: 7, timestamp: "Sep 27 02:10:40", ip: "185.220.101.9", user: null, action: "firewall_block", log_type: "syslog", raw_line: "Sep 27 02:10:40 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:11 SRC=185.220.101.9 DST=10.0.0.5 PROTO=TCP SPT=51000 DPT=22 WINDOW=1024" },

    { id: 6, timestamp: "27/Sep/2026:01:00:00 +0000", ip: "10.0.0.20", user: null, action: "http_request", log_type: "web", raw_line: '10.0.0.20 - - [27/Sep/2026:01:00:00 +0000] "GET /health HTTP/1.1" 200 32 "-" "curl/8.4.0"' },
    { id: 5, timestamp: "Sep 27 00:45:00", ip: null, user: null, action: "syslog_event", log_type: "syslog", raw_line: "Sep 27 00:45:00 fw01 kernel: CPU temperature above threshold" },
    { id: 4, timestamp: "Sep 27 00:30:00", ip: null, user: "deploy", action: "ssh_session_opened", log_type: "auth", raw_line: "Sep 27 00:30:00 web01 sudo: pam_unix(sudo:session): session opened for user deploy by alice(uid=1000)" },
    { id: 3, timestamp: "27/Sep/2026:00:10:07 +0000", ip: "10.0.0.15", user: null, action: "http_request", log_type: "web", raw_line: '10.0.0.15 - - [27/Sep/2026:00:10:07 +0000] "GET /assets/app.css HTTP/1.1" 200 4096 "-" "Mozilla/5.0"' },
    { id: 2, timestamp: "27/Sep/2026:00:10:05 +0000", ip: "10.0.0.15", user: null, action: "http_request", log_type: "web", raw_line: '10.0.0.15 - - [27/Sep/2026:00:10:05 +0000] "GET / HTTP/1.1" 200 1024 "-" "Mozilla/5.0"' },
    { id: 1, timestamp: "Sep 27 00:10:00", ip: "10.0.0.15", user: "alice", action: "ssh_login_success", log_type: "auth", raw_line: "Sep 27 00:10:00 web01 sshd[9001]: Accepted password for alice from 10.0.0.15 port 51124 ssh2" }
  ];

  window.LogAnalyzer.services.mockData = {
    SUMMARY: SUMMARY,
    STATS: STATS,
    THREATS: THREATS,
    EVENTS: EVENTS
  };
})();
