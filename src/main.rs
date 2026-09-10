// Сканер папок на наличие паролей и SSH-ключей — Rust-аналог scan_folder.py.
//
// Использование:
//   dcap-scan <папка> <лог-файл|папка> [потоков] [--no-sniff] [-v] [--encoding utf-8] [--presidio]

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use chrono::Local;
use crossbeam_channel::{bounded, unbounded, Receiver, Sender};
use regex::Regex;

// ---------------------------------------------------------------------------
// Константы
// ---------------------------------------------------------------------------

const MAX_FILE_SIZE: u64 = 50 * 1024 * 1024; // 50 MB
const MAX_TEXT_SIZE: usize = 200_000; // МАКСИМАЛЬНЫЙ размер текста для сканирования
const FILE_Q_SIZE: usize = 8192; // ограниченная очередь файлов

/// Расширения, которые сканируются как текст
const TEXT_EXTENSIONS: &[&str] = &[
    "txt", "csv", "log", "json", "xml", "yaml", "yml", "toml", "ini", "cfg", "conf", "env",
    "properties", "py", "js", "ts", "jsx", "tsx", "java", "c", "cpp", "h", "hpp", "cs", "go",
    "rs", "php", "rb", "swift", "kt", "sh", "bash", "zsh", "ps1", "bat", "cmd", "vbs", "pl",
    "lua", "r", "sql", "html", "css", "scss", "less", "md", "rst", "dockerfile", "makefile",
    "tf", "hcl", "gradle", "sbt", "cmake", "pem", "key", "cert", "crt", "p12", "pfx", "jks",
    "doc", "docx", "xls", "xlsx",
];

/// Имена файлов без расширения, которые сканируются как текст
const NAME_PATTERNS: &[&str] = &[
    "dockerfile", "makefile", "rakefile", "gemfile", "procfile", "vagrantfile",
];

/// Пропускаемые директории
const SKIP_DIRS: &[&str] = &[
    "$recycle.bin", "system volume information", "tmp", "temp", "cache", ".git", "__pycache__",
    "venv", ".venv", "node_modules", ".tox", ".mypy_cache", ".pytest_cache", ".idea", ".vscode",
    "dist", "build", "site-packages", ".eggs", "egg-info",
];

/// Имена файлов-кредов по самому имени (проверяется независимо от расширения)
const CRED_FILE_NAMES: &[&str] = &[
    "passwd", "shadow", "gshadow", "master.passwd", ".htpasswd", ".netrc", "_netrc", ".pgpass",
    "credentials", ".credentials", "credentials.json", "credentials.conf", "secrets",
    "secrets.json", "secrets.yaml", "secrets.yml", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "kubeconfig", "kubeconfig.yaml", "admin.conf", "jaas.conf", "kafka_client_jaas.conf",
];

// ---------------------------------------------------------------------------
// Regex-паттерны (аналог _CRED_PATTERNS + _NETWORK_PASS_PATTERNS в Python)
// ---------------------------------------------------------------------------

#[allow(dead_code)]
struct Rule {
    name: &'static str,
    subcategory: &'static str,
    confidence: f64,
    entropy_check: bool,
    re: Regex,
}

macro_rules! rule {
    ($name:literal, $sub:literal, $conf:expr, $entropy:expr, $icase:expr, $multiline:expr, $src:expr) => {
        Rule {
            name: $name,
            subcategory: $sub,
            confidence: $conf,
            entropy_check: $entropy,
            re: regex::RegexBuilder::new($src)
                .case_insensitive($icase)
                .multi_line($multiline)
                .build()
                .expect("regex build failed"),
        }
    };
}

fn build_rules() -> Vec<Rule> {
    vec![
        rule!(
            "PASSWORD", "CRED_PASSWORD", 0.75, true, true, true,
            r#"(?:password|passwd|pwd|пароль|pass)\s*[:=]\s*['"]?([^\s'"\\]{4,128})['"]?"#
        ),
        rule!(
            "PASSWORD_QUOTED", "CRED_PASSWORD", 0.85, false, true, true,
            r#"(?:password|passwd|pwd|пароль|pass)\s*[:=]\s*['"]([^\s'"]{4,128})['"]"#
        ),
        rule!(
            "SSH_PRIVATE_KEY", "CRED_SSH_PRIVATE_KEY", 0.99, false, true, false,
            r#"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|DSA|PGP)\s+PRIVATE\s+KEY-----"#
        ),
        rule!(
            "SSH_PUBLIC_KEY", "CRED_SSH_PUBLIC_KEY", 0.95, false, false, false,
            r#"ssh-(?:rsa|dss|ed25519)\s+[A-Za-z0-9+/=]{100,}"#
        ),
        rule!(
            "SSH_KEY_FILE", "CRED_SSH_KEY_PATH", 0.70, false, true, false,
            r#"(?:id_rsa|id_dsa|id_ecdsa|id_ed25519|\.ssh/[\w._-]+)"#
        ),
        rule!(
            "API_KEY", "CRED_API_KEY", 0.85, true, true, true,
            r#"(?:api[_-]?key|apikey)\s*[:=]\s*['"]?([A-Za-z0-9]{20,64})['"]?"#
        ),
        rule!(
            "AWS_ACCESS_KEY", "CRED_AWS_ACCESS_KEY", 0.95, false, false, false, r#"AKIA[0-9A-Z]{16}"#
        ),
        rule!(
            "AWS_SECRET_KEY", "CRED_AWS_SECRET_KEY", 0.95, true, true, true,
            r#"(?:aws_secret_access_key|secret_key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"#
        ),
        rule!(
            "GITHUB_TOKEN", "CRED_GITHUB_TOKEN", 0.95, false, false, false,
            r#"ghp_[A-Za-z0-9]{36}"#
        ),
        rule!(
            "GITHUB_PAT", "CRED_GITHUB_TOKEN", 0.95, false, false, false,
            r#"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}"#
        ),
        rule!(
            "SLACK_TOKEN", "CRED_SLACK_TOKEN", 0.90, false, false, false,
            r#"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"#
        ),
        rule!(
            "JWT_TOKEN", "CRED_JWT_TOKEN", 0.90, false, false, false,
            r#"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"#
        ),
        rule!(
            "GENERIC_TOKEN", "CRED_GENERIC_TOKEN", 0.70, true, true, true,
            r#"(?:token|secret|access_key|private_key)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,128})['"]?"#
        ),
        rule!(
            "BEARER_TOKEN", "CRED_BEARER_TOKEN", 0.85, true, false, false,
            r#"Bearer\s+([A-Za-z0-9_\-\.]{20,})"#
        ),
        rule!(
            "DATABASE_URL", "CRED_DATABASE_URL", 0.90, false, true, false,
            r#"(?:postgresql|mysql|mongodb|redis|sqlite|postgres)://[^\s'"]+"#
        ),
        rule!(
            "PRIVATE_KEY_FILE", "CRED_PRIVATE_KEY_PATH", 0.80, false, true, false,
            r#"(?:private_key_file|key_file|ssl_key)\s*[:=]\s*['"]?([^\s'"]+\.pem)['"]?"#
        ),
        rule!(
            "DOTNET_CONNECTION_STRING", "CRED_CONN_STRING", 0.90, false, true, false,
            r#"(?:server|data source|address|host)\s*=\s*[^;\r\n'"]{1,120};(?:[^=\r\n'"]+=[^;\r\n'"]*;)*\s*password\s*=\s*([^;\r\n'"]{1,128})"#
        ),
        rule!(
            "URI_CREDENTIALS", "CRED_URI_PASSWORD", 0.90, false, true, false,
            r#"[\w+.-]{1,24}://[^:\s@/]{1,64}:([^@\s/"']{4,128})@[^\s/"']+"#
        ),
        rule!(
            "JDBC_URL", "CRED_JDBC", 0.90, false, true, false,
            r#"jdbc:[a-z0-9_]+:[^\s"']{0,150}?//[^:\s@/]+:([^@\s"';]{1,128})@[^\s"']+"#
        ),
        rule!(
            "JDBC_UA_PASSWORD", "CRED_JDBC", 0.90, false, true, false,
            r#"jdbc:[a-z0-9_]+:[^\s"']{0,150}?(?:user\s*id|username|uid|user)\s*=\s*[^;\s"']+;\s*(?:password|pwd)\s*=\s*([^;\s"']{1,128})"#
        ),
        rule!(
            "JAAS_KEYTAB", "CRED_KEYTAB_PATH", 0.80, false, false, false,
            r#"key[tT]ab\s*=\s*["']?([^"'\s;]{3,200})["']?"#
        ),
        rule!(
            "KERBEROS_KEYTAB", "CRED_KEYTAB_PATH", 0.80, false, true, false,
            r#"(?:kerberos|krb5)[^\n]{0,60}?keytab\s*[:=]\s*["']?([^"'\s;]{3,200})["']?"#
        ),
        rule!(
            "JAAS_PASSWORD", "CRED_PASSWORD", 0.85, true, true, false,
            r#"(?:password|passphrase)\s*=\s*"\s*([^"\s;]{4,128})\s*""#
        ),
        rule!(
            "KUBECONFIG_TOKEN", "CRED_KUBE_TOKEN", 0.90, true, true, true,
            r#"^\s*token\s*:\s*([A-Za-z0-9_.\-]{16,140})\s*$"#
        ),
        rule!(
            "KUBECONFIG_CLIENT_DATA", "CRED_KUBE_TLS_DATA", 0.90, false, true, false,
            r#"client-(?:key|certificate)-data\s*:\s*([A-Za-z0-9+/=]{50,})"#
        ),
        rule!(
            "ENV_CRED_VAR", "CRED_ENV_VAR", 0.85, true, true, false,
            r#"(?:^|\n)\s*[A-Za-z][A-Za-z0-9_]*(?:(?:_(?:token|secret|password|passwd|apikey|api_key|access_key|private_key|connection_string|credential|key))|(?:token|secret|password|passwd|apikey))\s*[:=]\s*['"]?([^\s"';]{4,180})['"]?"#
        ),
        rule!(
            "REDIS_REQUIREPASS", "CRED_REDIS", 0.90, true, true, true,
            r#"^\s*requirepass\s+([^\s"']{4,128})"#
        ),
        rule!(
            "SPRING_DATASOURCE", "CRED_SPRING", 0.75, true, true, false,
            r#"spring\s*[:._\- ]+\s*datasource\s*[:._\- ]+\s*(?:password|username)\s*[:=]\s*['"]?([^\s"';]{4,128})['"]?"#
        ),
        rule!(
            "JWT_SECRET", "CRED_JWT_SECRET", 0.90, true, true, true,
            r#"jwt(?:[_\-\s]*secret[_\-\s]*key|[_\-\s]*signing[_\-\s]*key|[_\-\s]*private[_\-\s]*key|[_\-\s]*secret|[_\-\s]*key)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{32,})['"]?"#
        ),
        rule!(
            "OAUTH_CLIENT_SECRET", "CRED_OAUTH", 0.90, true, true, true,
            r#"client_secret\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#
        ),
        rule!(
            "GENERIC_SECRET", "CRED_GENERIC_SECRET", 0.70, true, true, true,
            r#"(?:secret|password|credential|api[_-]?key|access[_-]?key|private[_-]?key|token|passwd)\s*[:=]\s*['"]?([A-Za-z0-9+/=_\-]{12,220})['"]?"#
        ),
        // --- NETWORK ---
        rule!(
            "NETWORK_PASSWORD", "CRED_PASSWORD", 0.80, true, true, false,
            r#"(?:password|pass|passwd|pwd)\s*[:=]\s*['"]([^\s'"]{3,128})['"]"#
        ),
        rule!(
            "ENV_PASSWORD", "CRED_PASSWORD", 0.90, true, true, false,
            r#"(?:DB_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD|REDIS_PASSWORD|MONGO_PASSWORD|SMTP_PASSWORD)\s*[:=]\s*['"]?([^\s'"]{3,128})['"]?"#
        ),
        rule!(
            "ENV_PASSWORD_GENERIC", "CRED_PASSWORD", 0.85, true, true, false,
            r#"(?:^|\n)\s*[A-Za-z_][A-Za-z0-9_]*(?:_?(?:password|passwd|pwd))\s*[:=]\s*['"]?([^\s"';]{4,180})['"]?"#
        ),
    ]
}

fn build_prefilter(rules: &[Rule]) -> Regex {
    let mut src = String::new();
    for (i, r) in rules.iter().enumerate() {
        if i > 0 {
            src.push('|');
        }
        src.push_str(&format!("(?:{})", r.re.as_str()));
    }
    regex::RegexBuilder::new(&src)
        .case_insensitive(true)
        .multi_line(true)
        .dot_matches_new_line(true)
        .build()
        .expect("prefilter regex build failed")
}

// ---------------------------------------------------------------------------
// Entropy / вспомогательные
// ---------------------------------------------------------------------------

fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let len = s.chars().count() as f64;
    let mut freq: HashMap<char, u64> = HashMap::new();
    for ch in s.chars() {
        *freq.entry(ch).or_insert(0) += 1;
    }
    let mut h = 0.0;
    for &count in freq.values() {
        let p = count as f64 / len;
        h -= p * p.log2();
    }
    h
}

/// Правила, у которых значение группы 1 — «секрет по имени» и его надо проверять
/// на плейсхолдеры/служебные слова, чтобы не ловить README, схемы и шаблоны.
/// Структурные правила (SSH-ключи, JWT, URI, JDBC, kubeconfig и т.п.) не фильтруем.
const PLACEHOLDER_CHECK_RULES: &[&str] = &[
    "PASSWORD",
    "PASSWORD_QUOTED",
    "API_KEY",
    "AWS_SECRET_KEY",
    "GENERIC_TOKEN",
    "GENERIC_SECRET",
    "BEARER_TOKEN",
    "NETWORK_PASSWORD",
    "ENV_PASSWORD",
    "ENV_PASSWORD_GENERIC",
    "ENV_CRED_VAR",
    "JAAS_PASSWORD",
    "SPRING_DATASOURCE",
    "REDIS_REQUIREPASS",
    "DOTNET_CONNECTION_STRING",
    "JDBC_UA_PASSWORD",
    "JWT_SECRET",
    "OAUTH_CLIENT_SECRET",
];

/// Является ли значение «не-секретом»: плейсхолдер, служебное слово, ссылка на
/// переменную, пример из документации. Если да — это почти наверняка не пароль.
fn value_is_placeholder(v: &str) -> bool {
    let s = v
        .trim()
        .trim_matches(['.', ',', ';', ':', '!', '?', '-'])
        .to_lowercase();
    if s.is_empty() {
        return true;
    }

    // Само слово-ключ и частые служебные/примерные значения.
    const WORDS: &[&str] = &[
        "password", "passwd", "pwd", "pass", "secret", "secrets", "token", "tokens", "apikey",
        "api_key", "credential", "credentials", "undefined", "unknown", "null", "none", "true",
        "false", "default", "sample", "example", "demo", "dummy", "test", "placeholder",
        "changeme", "change_me", "changethis", "changeit", "replaceme", "replace_me", "redacted",
        "hidden", "removed", "notset", "not_set", "not_configured", "to_be_set", "to_be_changed",
        "postgres", "redis", "mysql", "admin", "root", "guest", "toor", "letmein", "password1",
        "password123", "pass123", "pass1234", "secret123", "admin123", "yourpassword",
        "your_password", "yoursecret", "your_secret", "yourtoken", "your_token", "yourapikey",
        "your_api_key", "yourkey", "your_key", "yourvalue", "your_value", "xxxx", "xxxxx",
        "xxxxxx", "xxxxxxx", "xxxxxxxx", "1234", "12345", "123456", "1234567", "12345678",
        "123456789", "1234567890", "0000", "1111", "00000000", "11111111",
    ];
    if WORDS.contains(&s.as_str()) {
        return true;
    }

    // Ссылки на переменные окружения / шаблонные подстановки / HTML.
    if s.contains("${") || s.contains("{{") || s.contains("}}") || s.ends_with('}')
        || s.contains('%') || s.contains('<') || s.contains('>')
    {
        return true;
    }

    // Классические плейсхолдеры вида your_*, *_here, *example*, *changeme*.
    if s.starts_with("your_") || s.starts_with("your-") || s.ends_with("_here")
        || s.ends_with("-here") || s.contains("changeme") || s.contains("replaceme")
        || s.contains("example") || s.contains("placeholder")
    {
        return true;
    }

    // URL/почта вместо пароля.
    if s.contains("://") || s.contains("@.") {
        return true;
    }

    // Только цифры или один повторяющийся символ — типичные значения-заглушки.
    if s.chars().all(|c| c.is_ascii_digit())
        || s.chars().nth(1).map_or(false, |c| s.chars().all(|x| x == c))
    {
        return true;
    }

    // Строка вида NNN=... из строковых таблиц локализации/ресурсов
    // (например "1133=Install" после метки "Password:").
    let mut digits = 0;
    for c in s.chars() {
        if c.is_ascii_digit() {
            digits += 1;
        } else {
            break;
        }
    }
    if digits >= 1 && s.chars().nth(digits) == Some('=') {
        return true;
    }

    // Команда/вызов кода в значении вместо секрета (PowerShell-глаголы и похожее).
    for prefix in [
        "get-", "set-", "new-", "remove-", "add-", "invoke-", "import-", "export-", "test-",
        "write-", "read-", "update-", "convertto-", "select-", "stop-", "start-",
    ] {
        if s.starts_with(prefix) {
            return true;
        }
    }

    false
}

fn line_number_at(text: &str, byte_offset: usize) -> usize {
    let idx = text.floor_char_boundary(byte_offset.min(text.len()));
    text[..idx].bytes().filter(|&b| b == b'\n').count() + 1
}

fn is_credential_file(path: &Path) -> Option<&'static str> {
    let name = path.file_name()?.to_str()?.to_lowercase();
    let name = name.as_str();
    if name == ".env" || name.starts_with(".env.") {
        return Some("CRED_ENV_FILE");
    }
    if CRED_FILE_NAMES.contains(&name) {
        return Some("CRED_FILE_BY_NAME");
    }
    let parts: Vec<String> = path
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .map(|s| s.to_lowercase())
        .collect();
    if parts.iter().any(|s| s == ".kube") && name == "config" {
        return Some("CRED_KUBECONFIG");
    }
    if parts.iter().any(|s| s == ".docker") && name == "config.json" {
        return Some("CRED_DOCKER_CONFIG");
    }
    None
}

fn should_scan(path: &Path, sniff: bool) -> bool {
    let name_lower = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_default();

    if !ext.is_empty() && TEXT_EXTENSIONS.contains(&ext.as_str()) {
        return true;
    }
    if name_lower.is_empty() {
        return false;
    }
    if NAME_PATTERNS.contains(&name_lower.as_str()) || is_credential_file(path).is_some() {
        return true;
    }
    if sniff && ext.is_empty() {
        let mut f = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(_) => return false,
        };
        let mut buf = [0u8; 512];
        let n = f.read(&mut buf).unwrap_or(0);
        if n == 0 {
            return false;
        }
        let chunk = &buf[..n];
        let nulls = chunk.iter().filter(|&&b| b == 0).count();
        if nulls as f64 > (chunk.len() as f64) * 0.05 {
            return false;
        }
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Чтение текста / Office
// ---------------------------------------------------------------------------

fn take_first_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

fn decode_to_text(raw: &[u8]) -> String {
    match std::str::from_utf8(raw) {
        Ok(s) => s.to_string(),
        Err(_) => {
            let (cow, _, _) = encoding_rs::WINDOWS_1251.decode(raw);
            cow.into_owned()
        }
    }
}

fn read_file_text(path: &Path, encoding: &str, sniff: bool) -> Result<String, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("не удалось получить метаданные: {e}"))?;
    if sniff && meta.len() > MAX_FILE_SIZE {
        return Err(format!(
            "файл превышает лимит размера ({} МБ)",
            MAX_FILE_SIZE / 1024 / 1024
        ));
    }
    let mut f =
        std::fs::File::open(path).map_err(|e| format!("не удалось открыть файл: {e}"))?;
    let mut raw = Vec::with_capacity(meta.len() as usize);
    f.read_to_end(&mut raw)
        .map_err(|e| format!("ошибка чтения файла: {e}"))?;
    let text = match encoding {
        "cp1251" | "windows-1251" => {
            let (cow, _, _) = encoding_rs::WINDOWS_1251.decode(&raw);
            cow.into_owned()
        }
        _ => decode_to_text(&raw),
    };
    Ok(take_first_chars(&text, MAX_TEXT_SIZE))
}

fn strip_office_tags(xml: &str) -> String {
    let mut s = xml.to_string();
    let w_p = Regex::new(r"</w:p>").unwrap();
    let w_tab = Regex::new(r"<w:tab\b[^>]*/>").unwrap();
    let tags = Regex::new(r"<[^>]+>").unwrap();
    s = w_p.replace_all(&s, "\n").into_owned();
    s = w_tab.replace_all(&s, "\t").into_owned();
    tags.replace_all(&s, "").into_owned()
}

fn unescape_html(s: &str) -> String {
    let numeric = Regex::new(r"&#(x?[0-9a-fA-F]+);").unwrap();
    let mut out = String::with_capacity(s.len());
    let mut last = 0;
    for caps in numeric.captures_iter(s) {
        if let Some(m) = caps.get(0) {
            out.push_str(&s[last..m.start()]);
            let code = caps.get(1).unwrap().as_str();
            let val = if code.get(..1).map_or(false, |c| c.eq_ignore_ascii_case("x")) {
                u32::from_str_radix(&code[1..], 16).ok()
            } else {
                code.parse::<u32>().ok()
            };
            match val {
                Some(v) => out.push(char::from_u32(v).unwrap_or('\u{FFFD}')),
                None => out.push_str(m.as_str()),
            }
            last = m.end();
        }
    }
    out.push_str(&s[last..]);
    for (from, to) in [
        ("&amp;", "&"),
        ("&lt;", "<"),
        ("&gt;", ">"),
        ("&quot;", "\""),
        ("&apos;", "'"),
        ("&nbsp;", " "),
    ] {
        out = out.replace(from, to);
    }
    out
}

fn extract_docx(data: &[u8]) -> Option<String> {
    let cursor = std::io::Cursor::new(data.to_vec());
    let mut zip = zip::ZipArchive::new(cursor).ok()?;
    let mut file = zip.by_name("word/document.xml").ok()?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).ok()?;
    let xml = String::from_utf8_lossy(&bytes);
    Some(unescape_html(&strip_office_tags(&xml)))
}

fn extract_xlsx(data: &[u8]) -> Option<String> {
    let cursor = std::io::Cursor::new(data.to_vec());
    let mut zip = zip::ZipArchive::new(cursor).ok()?;
    let names: Vec<String> = zip.file_names().map(|s| s.to_string()).collect();
    let mut parts: Vec<String> = Vec::new();
    for n in names.iter() {
        if n == "xl/sharedStrings.xml" || (n.starts_with("xl/worksheets/") && n.ends_with(".xml")) {
            if let Ok(mut file) = zip.by_name(n) {
                let mut bytes = Vec::new();
                if file.read_to_end(&mut bytes).is_ok() {
                    let xml = String::from_utf8_lossy(&bytes);
                    parts.push(strip_office_tags(&xml));
                }
            }
        }
    }
    if parts.is_empty() {
        return None;
    }
    Some(unescape_html(&parts.join("\n")))
}

fn extract_ole_strings(data: &[u8]) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();

    let text16: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let s16: String = String::from_utf16_lossy(&text16);
    let cleaned16: String = s16
        .chars()
        .map(|ch| if ch.is_alphanumeric() || char::is_ascii_punctuation(&ch) || ch == '\t' { ch } else { '\n' })
        .collect();
    let collapsed16 = collapse_newlines(&cleaned16);
    let lines16: Vec<String> = collapsed16
        .split('\n')
        .map(|ln| ln.trim().to_string())
        .filter(|ln| ln.chars().count() >= 4)
        .collect();
    if !lines16.is_empty() {
        parts.push(lines16.join("\n"));
    }

    let (cow, _, _) = encoding_rs::WINDOWS_1251.decode(data);
    let s1251 = cow.into_owned();
    let cleaned1251: String = s1251
        .chars()
        .map(|ch| if ch.is_alphanumeric() || char::is_ascii_punctuation(&ch) || ch == '\t' { ch } else { '\n' })
        .collect();
    let collapsed1251 = collapse_newlines(&cleaned1251);
    let lines1251: Vec<String> = collapsed1251
        .split('\n')
        .map(|ln| ln.trim().to_string())
        .filter(|ln| ln.chars().count() >= 4)
        .collect();
    if !lines1251.is_empty() {
        parts.push(lines1251.join("\n"));
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join("\n"))
    }
}

fn collapse_newlines(s: &str) -> String {
    let re = Regex::new(r"\n{2,}").unwrap();
    re.replace_all(s, "\n").into_owned()
}

fn extract_office_text(path: &Path) -> Result<String, String> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    let meta = std::fs::metadata(path).map_err(|e| format!("не удалось получить метаданные: {e}"))?;
    if meta.len() > MAX_FILE_SIZE {
        return Err(format!(
            "файл превышает лимит размера ({} МБ)",
            MAX_FILE_SIZE / 1024 / 1024
        ));
    }
    let data = std::fs::read(path).map_err(|e| format!("ошибка чтения файла: {e}"))?;
    match ext.as_str() {
        "docx" => extract_docx(&data).ok_or_else(|| {
            "не удалось извлечь текст (повреждённый или не поддерживаемый docx-файл)".to_string()
        }),
        "xlsx" => extract_xlsx(&data).ok_or_else(|| {
            "не удалось извлечь текст (повреждённый или не поддерживаемый xlsx-файл)".to_string()
        }),
        "doc" | "xls" => extract_ole_strings(&data).ok_or_else(|| {
            "не удалось извлечь текст (повреждённый или не поддерживаемый OLE-файл)".to_string()
        }),
        _ => Err("неподдерживаемый формат".to_string()),
    }
}

fn read_file_text_or_office(path: &Path, encoding: &str, sniff: bool) -> Result<String, String> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    if matches!(ext.as_str(), "doc" | "docx" | "xls" | "xlsx") {
        extract_office_text(path)
    } else {
        read_file_text(path, encoding, sniff)
    }
}

// ---------------------------------------------------------------------------
// Находка / статистика
// ---------------------------------------------------------------------------

#[allow(dead_code)]
#[derive(Clone)]
struct Finding {
    path: String,
    subcategory: String,
    value: String,
    line_number: usize,
    confidence: f64,
    context: String,
}

#[derive(Default)]
struct Shared {
    files_scanned: usize,
    files_skipped: usize,
    files_error: usize,
    dir_error: usize,
    find_count: usize,
    by_subcategory: HashMap<String, usize>,
    seen_keys: HashSet<String>,
    flagged_files: Vec<String>,
    file_types: HashMap<String, HashSet<String>>,
    failures: Vec<(String, String)>,
    findings: Vec<Finding>,
}

// ---------------------------------------------------------------------------
// State (persistence выполненной работы для возобновления)
// ---------------------------------------------------------------------------

/// События, которые воркеры отправляют в поток записи state-файла.
/// Секреты (значения) здесь никогда не пишутся — только пути и подкатегории.
#[derive(Debug)]
enum StateEvent {
    Processed(String),
    Finding(String, String),
    Failed(String, String),
}

#[derive(Clone, Default)]
struct StateSeed {
    processed: HashSet<String>,
    findings: Vec<(String, String)>,
    failures: Vec<(String, String)>,
}

/// Читает state-файл. Если папка в заголовке не совпадает с текущей —
/// начинаем с нуля (seed без данных).
fn load_state(path: &Path, folder: &str) -> StateSeed {
    let mut seed = StateSeed::default();
    let Ok(content) = std::fs::read_to_string(path) else {
        return seed;
    };
    let mut folder_ok = false;
    for line in content.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(f) = line.strip_prefix("# folder: ") {
            folder_ok = f.trim() == folder;
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split('\t');
        match parts.next() {
            Some("P") => {
                if let Some(p) = parts.next() {
                    if !p.is_empty() {
                        seed.processed.insert(p.to_string());
                    }
                }
            }
            Some("F") => {
                let p = parts.next().unwrap_or_default().to_string();
                let s = parts.next().unwrap_or_default().to_string();
                if !p.is_empty() && !s.is_empty() {
                    seed.findings.push((p, s));
                }
            }
            Some("E") => {
                let p = parts.next().unwrap_or_default().to_string();
                let r = parts.next().unwrap_or_default().to_string();
                if !p.is_empty() {
                    seed.failures.push((p.clone(), r));
                    seed.processed.insert(p);
                }
            }
            _ => {}
        }
    }
    // Грязный state от другой папки не используем.
    if !folder_ok {
        return StateSeed::default();
    }
    // Если файл не был доведён до конца (нет P/E-маркера), его находки
    // могли записаться лишь частично — отбрасываем их, чтобы не задвоить
    // при повторном сканировании этого файла.
    seed.findings.retain(|(p, _)| seed.processed.contains(p));
    seed
}

/// Формирует начальное состояние из сохранённого (восстанавливает прежние
/// находки и ошибки, чтобы итоговый отчёт был полным после возобновления).
fn seed_of(seed: &StateSeed) -> Shared {
    let mut s = Shared::default();
    for (p, sub) in &seed.findings {
        s.find_count += 1;
        *s.by_subcategory.entry(sub.clone()).or_insert(0) += 1;
        s.file_types.entry(p.clone()).or_default().insert(sub.clone());
        if !s.flagged_files.contains(p) {
            s.flagged_files.push(p.clone());
        }
    }
    s.failures = seed.failures.clone();
    s
}

/// Поток-писатель state-файла: переписывает заголовок + сохранённые данные,
/// потом дописывает новые события.
#[allow(clippy::type_complexity)]
fn spawn_state_writer(
    path: &Path,
    folder: &str,
    seed: &StateSeed,
    rx: Receiver<StateEvent>,
) -> std::thread::JoinHandle<()> {
    let f = std::fs::File::create(path).expect("не удалось создать state-файл");
    let mut w = BufWriter::new(f);
    let _ = writeln!(w, "# dcap-scan-state v1");
    let _ = writeln!(w, "# folder: {}", folder);
    let _ = writeln!(w, "# started: {}", Local::now().format("%Y-%m-%d %H:%M:%S"));
    for p in &seed.processed {
        let _ = writeln!(w, "P\t{}", p);
    }
    for (p, s) in &seed.findings {
        let _ = writeln!(w, "F\t{}\t{}", p, s);
    }
    for (p, r) in &seed.failures {
        let _ = writeln!(w, "E\t{}\t{}", p, r);
    }
    std::thread::spawn(move || {
        while let Ok(ev) = rx.recv() {
            match ev {
                StateEvent::Processed(p) => {
                    let _ = writeln!(w, "P\t{}", p);
                }
                StateEvent::Finding(p, s) => {
                    let _ = writeln!(w, "F\t{}\t{}", p, s);
                }
                StateEvent::Failed(p, r) => {
                    let _ = writeln!(w, "E\t{}\t{}", p, r);
                }
            }
            let _ = w.flush();
        }
        let _ = w.flush();
    })
}

/// Пишет итоговый отчёт в лог-файл: файлы с находками + типы секретов
/// (без значений!) и файлы, которые не удалось обработать + причина.
fn write_report(
    log_path: &Path,
    folder: &Path,
    shared: &Shared,
    threads: usize,
    resumed: usize,
) {
    let mut out = String::new();
    out.push_str("# dcap-secret-scanner — отчёт\n");
    out.push_str(&format!("# Папка:       {}\n", folder.display()));
    out.push_str(&format!("# Дата:        {}\n", Local::now().format("%Y-%m-%d %H:%M:%S")));
    out.push_str(&format!("# Потоков:     {}\n", threads));
    out.push_str(&format!(
        "# Файлов:      {} скан | {} пропуск | {} ошибок | {} возобновлено\n",
        shared.files_scanned, shared.files_skipped, shared.files_error, resumed
    ));
    out.push_str(&format!("# Каталогов с ошибкой: {}\n", shared.dir_error));
    out.push_str(&format!("# Находок:     {}\n", shared.find_count));
    out.push('\n');

    out.push_str("[ФАЙЛЫ С НАХОДКАМИ]\n");
    if shared.file_types.is_empty() {
        out.push_str("  (нет)\n");
    } else {
        let mut files: Vec<&String> = shared.file_types.keys().collect();
        files.sort();
        for f in files {
            out.push_str(&format!("  {}\n", f));
            let mut types: Vec<String> = shared.file_types[f].iter().map(|s| s.to_string()).collect();
            types.sort();
            out.push_str(&format!("    {}\n", types.join(", ")));
        }
    }
    out.push('\n');

    out.push_str("[НАХОДКИ]\n");
    if shared.findings.is_empty() {
        out.push_str("  (нет)\n");
    } else {
        for f in &shared.findings {
            out.push_str(&format!(
                "  {}:{} :: {} (conf {:.2})\n",
                f.path, f.line_number, f.subcategory, f.confidence
            ));
            out.push_str(&format!("      value: {}\n", f.value));
            if !f.context.is_empty() {
                out.push_str(&format!("      context: {}\n", f.context));
            }
        }
    }
    out.push('\n');

    out.push_str("[НЕ УДАЛОСЬ ОБРАБОТАТЬ]\n");
    if shared.failures.is_empty() {
        out.push_str("  (нет)\n");
    } else {
        for (p, r) in &shared.failures {
            out.push_str(&format!("  {} :: {}\n", p, r));
        }
    }

    if let Ok(mut f) = std::fs::File::create(log_path) {
        let _ = f.write_all(out.as_bytes());
    }
}

// ---------------------------------------------------------------------------
// Обход каталогов + сканирование
// ---------------------------------------------------------------------------

struct WalkState {
    q: VecDeque<PathBuf>,
    pending: usize,
    finished: bool,
}

struct ScanOut {
    files_scanned: usize,
    files_skipped: usize,
    files_error: usize,
    dir_error: usize,
    resumed: usize,
    find_count: usize,
    by_subcategory: HashMap<String, usize>,
}

fn run_scan(
    folder: &Path,
    log_path: &Path,
    encoding: &str,
    sniff: bool,
    verbose: bool,
    threads: usize,
    state_path: Option<&Path>,
    tuning: Tuning,
) -> ScanOut {
    let rules = Arc::new(build_rules());
    let prefilter = Arc::new(build_prefilter(&rules));

    // State: загрузка предыдущей работы (если задан --state)
    let canonical_folder = folder.to_string_lossy().into_owned();
    let seed = match state_path {
        Some(sp) => load_state(sp, &canonical_folder),
        None => StateSeed::default(),
    };
    let resume_processed = Arc::new(seed.processed.clone());
    let resumed = Arc::new(AtomicUsize::new(0));

    let state = Arc::new((Mutex::new(WalkState {
        q: VecDeque::from([folder.to_path_buf()]),
        pending: 1,
        finished: false,
    }), Condvar::new()));

    let (file_tx, file_rx): (Sender<Option<PathBuf>>, Receiver<Option<PathBuf>>) =
        bounded(FILE_Q_SIZE);

    let produced = Arc::new(AtomicUsize::new(0));
    let total_subdirs = Arc::new(AtomicUsize::new(0));
    let skipped_walk = Arc::new(AtomicUsize::new(0));
    let shared = Arc::new(Mutex::new(seed_of(&seed)));
    let processed = Arc::new(AtomicUsize::new(0));
    let start = Instant::now();

    // Канал событий для state-файла + поток-писатель
    let (state_tx, state_writer_handle): (Option<Sender<StateEvent>>, Option<_>) = match state_path {
        Some(sp) => {
            let (tx, rx) = unbounded();
            let handle = spawn_state_writer(sp, &canonical_folder, &seed, rx);
            (Some(tx), Some(handle))
        }
        None => (None, None),
    };

    // Воркеры каталогов
    let mut dir_handles = Vec::new();
    for _ in 0..threads {
        let state = state.clone();
        let file_tx = file_tx.clone();
        let produced = produced.clone();
        let total_subdirs = total_subdirs.clone();
        let skipped_walk = skipped_walk.clone();
        let resume_processed = resume_processed.clone();
        let resumed = resumed.clone();
        let sniff = sniff;
        let shared = shared.clone();
        dir_handles.push(std::thread::spawn(move || {
            loop {
                let dir = {
                    let lock = &state.0;
                    let cvar = &state.1;
                    let mut st = lock.lock().unwrap();
                    while st.q.is_empty() && !st.finished {
                        st = cvar.wait(st).unwrap();
                    }
                    if st.q.is_empty() && st.finished {
                        return;
                    }
                    st.q.pop_front().unwrap()
                };
                match std::fs::read_dir(&dir) {
                    Ok(entries) => {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            let ft = match entry.file_type() {
                                Ok(ft) => ft,
                                Err(e) => {
                                    let mut s = shared.lock().unwrap();
                                    s.dir_error += 1;
                                    s.failures.push((
                                        path.to_string_lossy().into_owned(),
                                        format!("не удалось получить тип записи: {e}"),
                                    ));
                                    continue;
                                }
                            };
                            if ft.is_symlink() {
                                if path.is_dir() {
                                    continue; // симлинк на каталог не обходим
                                }
                            } else if ft.is_dir() {
                                let lname = entry.file_name().to_string_lossy().to_lowercase();
                                if SKIP_DIRS.contains(&lname.as_str()) {
                                    continue;
                                }
                                {
                                    let lock = &state.0;
                                    let mut st = lock.lock().unwrap();
                                    // не блокируемся на неограниченном deque
                                    st.q.push_back(path.clone());
                                    st.pending += 1;
                                    total_subdirs.fetch_add(1, Ordering::Relaxed);
                                    drop(st);
                                }
                                continue;
                            }
                            if !should_scan(&path, sniff) {
                                skipped_walk.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                            // Пропускаем уже обработанные при возобновлении
                            let pstr = path.to_string_lossy().into_owned();
                            if !resume_processed.is_empty() && resume_processed.contains(&pstr) {
                                resumed.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                            produced.fetch_add(1, Ordering::Relaxed);
                            if file_tx.send(Some(path)).is_err() {
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        let mut s = shared.lock().unwrap();
                        s.dir_error += 1;
                        s.failures.push((
                            dir.to_string_lossy().into_owned(),
                            format!("не удалось прочитать каталог: {e}"),
                        ));
                    }
                }
                {
                    let lock = &state.0;
                    let cvar = &state.1;
                    let mut st = lock.lock().unwrap();
                    st.pending -= 1;
                    if st.pending == 0 && !st.finished {
                        st.finished = true;
                        for _ in 0..threads {
                            let _ = file_tx.send(None);
                        }
                    }
                    cvar.notify_all();
                }
            }
        }));
    }
    drop(file_tx);

    // Воркеры сканирования
    let mut work_handles = Vec::new();
    for _ in 0..threads {
        let file_rx = file_rx.clone();
        let rules = rules.clone();
        let prefilter = prefilter.clone();
        let shared = shared.clone();
        let processed = processed.clone();
        let encoding = encoding.to_string();
        let sniff = sniff;
        let verbose = verbose;
        let tuning = tuning;
        let state_tx = state_tx.clone();
        work_handles.push(std::thread::spawn(move || {
            while let Ok(item) = file_rx.recv() {
                let Some(path) = item else { break };
                process_file(
                    &path,
                    &encoding,
                    sniff,
                    verbose,
                    &rules,
                    &prefilter,
                    &shared,
                    state_tx.as_ref(),
                    tuning,
                );
                processed.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }
    drop(file_rx);

    // Прогресс
    let progress_done = Arc::new(AtomicBool::new(false));
    {
        let progress_done = progress_done.clone();
        let processed = processed.clone();
        let start = start;
        std::thread::spawn(move || {
            let mut last = 0usize;
            let mut last_t = Instant::now();
            while !progress_done.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(2000));
                if progress_done.load(Ordering::Relaxed) {
                    break;
                }
                let now = processed.load(Ordering::Relaxed);
                let _t = start.elapsed().as_secs_f64();
                let dt = (Instant::now() - last_t).as_secs_f64();
                let rate = if dt > 0.0 {
                    (now - last) as f64 / dt
                } else {
                    0.0
                };
                eprint!("\rОбработано: {} файлов ({:.0}/s)          ", now, rate);
                let _ = std::io::stderr().flush();
                last = now;
                last_t = Instant::now();
            }
            eprint!("\r                                                      \r");
        });
    }

    for h in work_handles {
        let _ = h.join();
    }
    for h in dir_handles {
        let _ = h.join();
    }

    // Закрываем канал state-событий и ждём, пока писатель допишет файл
    drop(state_tx);
    if let Some(h) = state_writer_handle {
        let _ = h.join();
    }

    progress_done.store(true, Ordering::Relaxed);

    let elapsed = start.elapsed().as_secs_f64();
    let produced_n = produced.load(Ordering::Relaxed);
    let subdirs_n = total_subdirs.load(Ordering::Relaxed);
    let resumed_n = resumed.load(Ordering::Relaxed);

    {
        let mut shared_guard = shared.lock().unwrap();
        shared_guard.files_skipped += skipped_walk.load(Ordering::Relaxed);
    }

    println!("[i] Файлов к обработке: {produced_n}, подпапок: {subdirs_n}");
    let dir_errors = shared.lock().unwrap().dir_error;
    if dir_errors > 0 {
        println!("[!] Каталогов, которые не удалось прочитать: {dir_errors} — см. [НЕ УДАЛОСЬ ОБРАБОТАТЬ] в логе");
    }
    println!("[i] Время: {elapsed:.1} сек");

    let out = {
        let g = shared.lock().unwrap();
        let out = ScanOut {
            files_scanned: g.files_scanned,
            files_skipped: g.files_skipped,
            files_error: g.files_error,
            dir_error: g.dir_error,
            resumed: resumed_n,
            find_count: g.find_count,
            by_subcategory: g.by_subcategory.clone(),
        };
        write_report(log_path, folder, &g, threads, resumed_n);
        out
    };
    out
}

fn process_file(
    path: &Path,
    encoding: &str,
    sniff: bool,
    verbose: bool,
    rules: &[Rule],
    prefilter: &Regex,
    shared: &Mutex<Shared>,
    state_tx: Option<&Sender<StateEvent>>,
    tuning: Tuning,
) {
    let path_str = path.to_string_lossy().into_owned();
    let hint = is_credential_file(path);
    if let Some(sub) = hint {
        let value = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        add_finding(
            shared,
            path_str.clone(),
            sub.to_string(),
            value,
            0,
            0.90,
            path_str.clone(),
            "filename".to_string(),
            state_tx,
        );
    }

    let text = match read_file_text_or_office(path, encoding, sniff) {
        Ok(t) => t,
        Err(reason) => {
            let mut s = shared.lock().unwrap();
            s.files_error += 1;
            s.failures.push((path_str.clone(), reason.clone()));
            if let Some(tx) = state_tx {
                let _ = tx.send(StateEvent::Failed(path_str.clone(), reason));
            }
            return;
        }
    };

    {
        let mut s = shared.lock().unwrap();
        s.files_scanned += 1;
    }

    scan_text(&path_str, &text, rules, prefilter, shared, verbose, state_tx, &tuning);

    if let Some(tx) = state_tx {
        let _ = tx.send(StateEvent::Processed(path_str.clone()));
    }
}

fn add_finding(
    shared: &Mutex<Shared>,
    path: String,
    subcategory: String,
    value: String,
    line_number: usize,
    confidence: f64,
    context: String,
    _method: String,
    state_tx: Option<&Sender<StateEvent>>,
) {
    let key_bytes = take_first_chars(&value, 100);
    let key = format!("{path}:{subcategory}:{key_bytes}");
    let mut s = shared.lock().unwrap();
    if s.seen_keys.contains(&key) {
        return;
    }
    s.seen_keys.insert(key.clone());
    s.find_count += 1;
    *s.by_subcategory.entry(subcategory.clone()).or_insert(0) += 1;
    let is_new_file = !s.flagged_files.contains(&path);
    if is_new_file {
        s.flagged_files.push(path.clone());
    }
    s.file_types.entry(path.clone()).or_default().insert(subcategory.clone());
    s.findings.push(Finding {
        path: path.clone(),
        subcategory: subcategory.clone(),
        value: take_first_chars(&value, 500),
        line_number,
        confidence,
        context: take_first_chars(&context, 500),
    });
    drop(s);
    if let Some(tx) = state_tx {
        let _ = tx.send(StateEvent::Finding(path, subcategory));
    }
}

fn scan_text(
    path: &str,
    text: &str,
    rules: &[Rule],
    prefilter: &Regex,
    shared: &Mutex<Shared>,
    _verbose: bool,
    state_tx: Option<&Sender<StateEvent>>,
    tuning: &Tuning,
) {
    if prefilter.find(text).is_none() {
        return;
    }
    for rule in rules {
        for caps in rule.re.captures_iter(text) {
            let m = caps.get(1).or_else(|| caps.get(0));
            let Some(m) = m else { continue };
            let value = m.as_str();
            if value.chars().count() < tuning.min_length {
                continue;
            }
            if tuning.no_generic
                && (rule.name == "GENERIC_SECRET" || rule.name == "GENERIC_TOKEN")
            {
                continue;
            }
            if rule.confidence < tuning.confidence_threshold {
                continue;
            }
            if rule.entropy_check && shannon_entropy(value) < tuning.min_entropy {
                continue;
            }
            if PLACEHOLDER_CHECK_RULES.contains(&rule.name) {
                if value_is_placeholder(value) {
                    continue;
                }
                // Маркеры комментариев/документации: #, //, ;, *, --, <!--, !
                if is_comment_line(text, m.start()) {
                    continue;
                }
                if tuning.require_mixed && !looks_like_real_secret(value) {
                    continue;
                }
                if tuning.strict_filter && value_flagged_by_strict_filter(value) {
                    continue;
                }
            }
            let line_num = line_number_at(text, m.start());
            let start = text.floor_char_boundary(m.start().saturating_sub(80));
            let end = text.floor_char_boundary((m.end() + 80).min(text.len()));
            let mut ctx = text[start..end].replace('\n', " ").trim().to_string();
            ctx = take_first_chars(&ctx, 500);
            add_finding(
                shared,
                path.to_string(),
                rule.subcategory.to_string(),
                value.to_string(),
                line_num,
                rule.confidence,
                ctx,
                "regex".to_string(),
                state_tx,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// Пороги фильтрации, управляемые из командной строки.
#[derive(Clone, Copy)]
struct Tuning {
    min_entropy: f64,
    min_length: usize,
    no_generic: bool,
    confidence_threshold: f64,
    require_mixed: bool,
    strict_filter: bool,
}

impl Default for Tuning {
    fn default() -> Self {
        Tuning {
            min_entropy: 3.0,
            min_length: 4,
            no_generic: false,
            confidence_threshold: 0.0,
            require_mixed: false,
            strict_filter: false,
        }
    }
}

/// Начинается ли строка совпадения с маркера комментария.
/// Применяется только к «правилам по значению» (не к структурным: SSH, JWT и т.п.).
fn is_comment_line(text: &str, match_start: usize) -> bool {
    let line_start = text[..match_start].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let before = text[line_start..match_start].trim_start();
    const MARKERS: &[&str] = &["#", "//", ";", "*", "--", "<!--", "!"];
    MARKERS.iter().any(|m| before.starts_with(m))
}

/// Значение похоже на «настоящий» секрет: длина >= 8 и минимум 3 из 4
/// категорий символов (верхний/нижний регистр, цифры, спецсимволы).
fn looks_like_real_secret(v: &str) -> bool {
    if v.chars().count() < 8 {
        return false;
    }
    let has_upper = v.chars().any(|c| c.is_uppercase());
    let has_lower = v.chars().any(|c| c.is_lowercase());
    let has_digit = v.chars().any(|c| c.is_ascii_digit());
    let has_special = v.chars().any(|c| !c.is_alphanumeric());
    let score = [has_upper, has_lower, has_digit, has_special]
        .iter()
        .filter(|&&x| x)
        .count();
    score >= 3
}

/// Экстра-фильтр плейсхолдеров (рискованный, включается только --strict-filter):
/// password123, example_123, simple_name, слишком короткие значения.
fn value_flagged_by_strict_filter(v: &str) -> bool {
    let s = v.trim().to_lowercase();
    if s.chars().count() < 6 {
        return true;
    }
    let stem = s.trim_end_matches(|c: char| c.is_ascii_digit());
    if ["password", "secret", "token", "pass", "pwd", "key"]
        .iter()
        .any(|w| stem == *w || s.starts_with(w))
    {
        return true;
    }
    if stem.ends_with('_') && stem.len() > 1 && s.chars().count() > stem.len() {
        return true; // example_123 / my_secret_2024
    }
    let parts: Vec<&str> = s.split('_').filter(|p| !p.is_empty()).collect();
    if parts.len() >= 2
        && parts
            .iter()
            .all(|p| p.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()))
    {
        return true; // simple_name
    }
    false
}

struct Args {
    folder: PathBuf,
    log: PathBuf,
    threads: usize,
    encoding: String,
    sniff: bool,
    verbose: bool,
    state: Option<PathBuf>,
    tuning: Tuning,
}

fn usage() -> ! {
    eprintln!(
        "Использование: dcap-scan <папка> <лог-файл|папка> [потоков] [--no-sniff] [--encoding enc] [--state <файл>] [-v] [--presidio]"
    );
    eprintln!("  --min-entropy <N>            мин. энтропия Шеннона (по умолчанию 3.0)");
    eprintln!("  --min-length <N>             мин. длина значения (по умолчанию 4)");
    eprintln!("  --no-generic                 отключить GENERAL_* правила");
    eprintln!("  --confidence-threshold <N>   мин. уверенность правила 0..1 (по умолчанию 0)");
    eprintln!("  --require-mixed              значение должно содержать >=3 из 4 категорий символов");
    eprintln!("  --strict-filter              экстра-фильтр плейсхолдеров (password123, simple_name, <6 симв.)");
    std::process::exit(1);
}

fn parse_args() -> Args {
    let mut it = std::env::args().skip(1);
    let mut positionals: Vec<String> = Vec::new();
    let mut sniff = true;
    let mut verbose = false;
    let mut encoding = "utf-8".to_string();
    let mut state: Option<PathBuf> = None;
    let mut threads_arg: Option<String> = None;
    let mut tuning = Tuning::default();

    while let Some(a) = it.next() {
        match a.as_str() {
            "--no-sniff" => sniff = false,
            "-v" | "--verbose" => verbose = true,
            "--no-generic" => tuning.no_generic = true,
            "--require-mixed" => tuning.require_mixed = true,
            "--strict-filter" => tuning.strict_filter = true,
            "--min-entropy" => match it.next().and_then(|v| v.parse::<f64>().ok()) {
                Some(v) if v.is_finite() && v >= 0.0 => tuning.min_entropy = v,
                _ => usage(),
            },
            "--min-length" => match it.next().and_then(|v| v.parse::<usize>().ok()) {
                Some(v) => tuning.min_length = v,
                None => usage(),
            },
            "--confidence-threshold" => match it
                .next()
                .and_then(|v| v.parse::<f64>().ok())
            {
                Some(v) if v.is_finite() && v >= 0.0 && v <= 1.0 => {
                    tuning.confidence_threshold = v;
                }
                _ => usage(),
            },
            "--presidio" => {
                eprintln!(
                    "[i] Presidio не поддерживается в Rust-версии, работает regex-режим"
                );
            }
            "--state" => match it.next() {
                Some(v) => state = Some(PathBuf::from(v)),
                None => usage(),
            },
            "--encoding" => match it.next() {
                Some(v) => encoding = v,
                None => usage(),
            },
            s if s.starts_with("--") => usage(),
            s if threads_arg.is_none() && s.chars().all(|c| c.is_ascii_digit()) => {
                threads_arg = Some(s.to_string());
            }
            _ => positionals.push(a),
        }
    }
    if positionals.len() < 2 {
        eprintln!("[!] Недостаточно аргументов: нужны <папка> и <лог>");
        std::process::exit(1);
    }
    let folder = PathBuf::from(&positionals[0]);
    let log = PathBuf::from(&positionals[1]);
    let threads = threads_arg
        .map(|s| s.parse::<usize>().unwrap_or(1))
        .unwrap_or(1)
        .clamp(1, 10);
    Args {
        folder,
        log,
        threads,
        encoding,
        sniff,
        verbose,
        state,
        tuning,
    }
}

fn resolve_log_path(arg: &Path) -> PathBuf {
    let ts = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let base = arg
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let is_dir = arg.is_dir();
    let is_file = arg
        .extension()
        .map(|e| !e.is_empty())
        .unwrap_or(false);
    let (dir, name) = if is_dir || (!is_file && base.is_empty()) || base.find('.').is_none() {
        (arg.to_path_buf(), format!("scan_{ts}.log"))
    } else {
        let stem = arg
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| base.clone());
        let ext = arg
            .extension()
            .map(|e| e.to_string_lossy().into_owned())
            .unwrap_or_default();
        let parent = arg.parent().unwrap_or(Path::new(".")).to_path_buf();
        (parent, format!("{stem}_{ts}.{ext}"))
    };
    let _ = std::fs::create_dir_all(&dir);
    dir.join(name)
}

fn main() {
    let args = parse_args();

    let folder = if args.folder.as_os_str().is_empty() {
        args.folder.clone()
    } else {
        let mut p = args.folder.clone();
        let s = p.to_string_lossy();
        let already_unc = s.starts_with("\\\\") || s.starts_with("//");
        if p.is_absolute() && !already_unc {
            if let Ok(c) = std::fs::canonicalize(&p) {
                let c = c.to_string_lossy().into_owned();
                if let Some(stripped) = c.strip_prefix("\\\\?\\") {
                    if let Some(unc) = stripped.strip_prefix("UNC\\") {
                        p = PathBuf::from(format!("\\\\{unc}"));
                    } else {
                        p = PathBuf::from(stripped);
                    }
                } else {
                    p = PathBuf::from(c);
                }
            }
        }
        p
    };
    if !folder.is_dir() {
        println!("[!] Папка не найдена: {}", folder.display());
        std::process::exit(1);
    }

    let log_path = resolve_log_path(&args.log);

    println!("[i] Сканирование: {}", folder.display());
    println!("[i] Лог: {}", log_path.display());
    println!("[i] Режим: regex");
    println!("[i] Потоков: {}", args.threads);
    println!(
        "[i] Sniff файлов без расширения: {}",
        if args.sniff { "вкл" } else { "выкл" }
    );
    println!(
        "[i] Тюнинг: min_entropy={} min_length={} confidence>={} no_generic={} require_mixed={} strict={}",
        args.tuning.min_entropy,
        args.tuning.min_length,
        args.tuning.confidence_threshold,
        args.tuning.no_generic,
        args.tuning.require_mixed,
        args.tuning.strict_filter,
    );
    if let Some(sp) = &args.state {
        println!("[i] State: {}", sp.display());
    }

    // Лог открываем/очищаем заранее
    if let Ok(f) = std::fs::File::create(&log_path) {
        drop(f);
    }

    let out = run_scan(
        &folder,
        &log_path,
        &args.encoding,
        args.sniff,
        args.verbose,
        args.threads,
        args.state.as_deref(),
        args.tuning,
    );

    println!();
    println!("{}", "=".repeat(60));
    println!("  Сканирование завершено");
    println!("  Папка:     {}", folder.display());
    println!("  Файлов:    {} скан | {} пропуск | {} ошибок | {} возобновлено",
        out.files_scanned, out.files_skipped, out.files_error, out.resumed,
    );
    if out.dir_error > 0 {
        println!("  [!] Каталогов не прочитано: {} (см. [НЕ УДАЛОСЬ ОБРАБОТАТЬ] в логе)", out.dir_error);
    }
    println!("  Находок:   {}", out.find_count);
    if !out.by_subcategory.is_empty() {
        println!();
        let mut sorted: Vec<(&String, &usize)> = out.by_subcategory.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        for (sub, count) in sorted {
            println!("    {sub}: {count}");
        }
    }
    println!("  Лог:       {}", log_path.display());
    println!("{}", "=".repeat(60));

    if out.find_count > 0 {
        std::process::exit(2);
    }
}