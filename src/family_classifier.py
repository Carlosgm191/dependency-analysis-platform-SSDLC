def classify_family(description: str) -> str:

    if not description:
        return "unknown"

    text = description.lower()

    families = {

        "sql_injection": [

            "sql injection",
            "inject sql",
            "database query",
            "unsanitized sql",
            "crafted sql"
        ],

        "xss": [

            "cross-site scripting",
            "xss",
            "script injection",
            "malicious javascript"
        ],

        "rce": [

            "remote code execution",
            "arbitrary code execution",
            "execute arbitrary code",
            "arbitrary python code",
            "code execution",
            "command execution",
            "shell execution"
        ],

        "dos": [

            "denial of service",
            "dos",
            "resource exhaustion",
            "cpu usage",
            "memory allocation",
            "resource consumption",
            "decompression bomb",
            "slow performance",
            "infinite loop",
            "crash",
            "application crash",
            "service unavailable"
        ],

        "path_traversal": [

            "directory traversal",
            "path traversal",
            "file traversal",
            "../",
            "arbitrary file read"
        ],

        "ssrf": [

            "ssrf",
            "server-side request forgery",
            "open redirect",
            "malicious redirect",
            "redirect"
        ],

        "credential_leak": [

            "credential leak",
            "credentials leak",
            "password leak",
            "token leak",
            "secret exposure",
            "netrc",
            "proxy-authorization",
            "sensitive information"
        ],

        "tls_security": [

            "tls",
            "ssl",
            "certificate verification",
            "certificate validation",
            "man-in-the-middle",
            "mitm",
            "https verification"
        ],

        "temp_file_race": [

            "predictable filename",
            "temporary directory",
            "race condition",
            "tmpdir",
            "temporary file"
        ],

        "sandbox_escape": [

            "sandbox escape",
            "sandboxed environment",
            "container escape"
        ],

        "header_injection": [

            "header spoofing",
            "header injection",
            "http header"
        ],

        "authentication_bypass": [

            "authentication bypass",
            "auth bypass",
            "authorization bypass",
            "improper authentication",
            "access control"
        ],

        "privilege_escalation": [

            "privilege escalation",
            "elevation of privilege",
            "gain elevated privileges"
        ],

        "information_disclosure": [

            "information disclosure",
            "information leak",
            "data leak",
            "sensitive data exposure",
            "exposes sensitive information"
        ],

        "deserialization": [

            "deserialization",
            "unsafe deserialization",
            "pickle",
            "yaml load"
        ]
    }

    for family, keywords in families.items():

        for keyword in keywords:

            if keyword in text:
                return family

    return "unknown"