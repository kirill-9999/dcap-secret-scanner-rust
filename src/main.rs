// Сканер папок на наличие паролей и SSH-ключей — Rust-аналог scan_folder.py.
//
// Использование:
//   dcap-scan <папка> <лог-файл|папка> [потоков] [--no-sniff] [-v] [--encoding utf-8] [--presidio]

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use chrono::Local;
use crossbeam_channel::{bounded, Receiver, Sender};
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
            "GENERIC_SECRET", "CRED_GENERIC_SECRET", 0.70, true, true, true,
            r#"(?:secret|password|credential|api[_-]?key|access[_-]?key|private[_-]?key|token|passwd)\s*[:=]\s*['"]?([A-Za-z0-9+/=_\-]{12,220})['"]?"#
        ),
        // --- NETWORK ---
        rule!(
            "NETWORK_PASSWORD", "CRED_PASSWORD", 0.80, true, true, false,
            r#"(?:password|pass|passwd|pwd)\s*[:=]\s*['"]([^\s'"]{3,128})['"]"#
        ),
        rule!(
            "ENV_PASSWORD", "CRED_PASSWORD", 0.90, false, true, false,
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

fn read_file_text(path: &Path, encoding: &str, sniff: bool) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if sniff && meta.len() > MAX_FILE_SIZE {
        return None;
    }
    let mut f = std::fs::File::open(path).ok()?;
    let mut raw = Vec::with_capacity(meta.len() as usize);
    if f.read_to_end(&mut raw).is_err() {
        return None;
    }
    let text = match encoding {
        "cp1251" | "windows-1251" => {
            let (cow, _, _) = encoding_rs::WINDOWS_1251.decode(&raw);
            cow.into_owned()
        }
        _ => decode_to_text(&raw),
    };
    Some(take_first_chars(&text, MAX_TEXT_SIZE))
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

fn extract_office_text(path: &Path) -> Option<String> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > MAX_FILE_SIZE {
        return None;
    }
    let data = std::fs::read(path).ok()?;
    match ext.as_str() {
        "docx" => extract_docx(&data),
        "xlsx" => extract_xlsx(&data),
        "doc" | "xls" => extract_ole_strings(&data),
        _ => None,
    }
}

fn read_file_text_or_office(path: &Path, encoding: &str, sniff: bool) -> Option<String> {
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
    find_count: usize,
    by_subcategory: HashMap<String, usize>,
    seen_keys: HashSet<String>,
    flagged_files: Vec<String>,
    findings: Vec<Finding>,
}

impl Shared {
    fn clone_inner(&self) -> Shared {
        Shared {
            files_scanned: self.files_scanned,
            files_skipped: self.files_skipped,
            files_error: self.files_error,
            find_count: self.find_count,
            by_subcategory: self.by_subcategory.clone(),
            seen_keys: HashSet::new(),
            flagged_files: Vec::new(),
            findings: Vec::new(),
        }
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
) -> ScanOut {
    let rules = Arc::new(build_rules());
    let prefilter = Arc::new(build_prefilter(&rules));

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
    let shared = Arc::new(Mutex::new(Shared::default()));
    let processed = Arc::new(AtomicUsize::new(0));
    let start = Instant::now();

    // Воркеры каталогов
    let mut dir_handles = Vec::new();
    for _ in 0..threads {
        let state = state.clone();
        let file_tx = file_tx.clone();
        let produced = produced.clone();
        let total_subdirs = total_subdirs.clone();
        let skipped_walk = skipped_walk.clone();
        let sniff = sniff;
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
                                Err(_) => continue,
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
                            produced.fetch_add(1, Ordering::Relaxed);
                            if file_tx.send(Some(path)).is_err() {
                                break;
                            }
                        }
                    }
                    Err(_) => {}
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
        let log_path = log_path.to_path_buf();
        let encoding = encoding.to_string();
        let sniff = sniff;
        let verbose = verbose;
        work_handles.push(std::thread::spawn(move || {
            while let Ok(item) = file_rx.recv() {
                let Some(path) = item else { break };
                process_file(
                    &path,
                    &log_path,
                    &encoding,
                    sniff,
                    verbose,
                    &rules,
                    &prefilter,
                    &shared,
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

    progress_done.store(true, Ordering::Relaxed);

    let elapsed = start.elapsed().as_secs_f64();
    let produced_n = produced.load(Ordering::Relaxed);
    let subdirs_n = total_subdirs.load(Ordering::Relaxed);

    {
        let mut shared_guard = shared.lock().unwrap();
        shared_guard.files_skipped += skipped_walk.load(Ordering::Relaxed);
    }

    println!("[i] Файлов к обработке: {produced_n}, подпапок: {subdirs_n}");
    println!("[i] Время: {elapsed:.1} сек");

    let final_shared = shared.lock().unwrap().clone_inner();
    ScanOut {
        files_scanned: final_shared.files_scanned,
        files_skipped: final_shared.files_skipped,
        find_count: final_shared.find_count,
        by_subcategory: final_shared.by_subcategory,
    }
}

fn process_file(
    path: &Path,
    log_path: &Path,
    encoding: &str,
    sniff: bool,
    verbose: bool,
    rules: &[Rule],
    prefilter: &Regex,
    shared: &Mutex<Shared>,
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
            log_path,
            sub.to_string(),
            value,
            0,
            0.90,
            path_str.clone(),
            "filename".to_string(),
        );
    }

    let text = match read_file_text_or_office(path, encoding, sniff) {
        Some(t) => t,
        None => {
            let mut s = shared.lock().unwrap();
            s.files_skipped += 1;
            return;
        }
    };

    {
        let mut s = shared.lock().unwrap();
        s.files_scanned += 1;
    }

    scan_text(
        &path_str,
        log_path,
        &text,
        rules,
        prefilter,
        shared,
        verbose,
    );
}

fn add_finding(
    shared: &Mutex<Shared>,
    path: String,
    log_path: &Path,
    subcategory: String,
    value: String,
    line_number: usize,
    confidence: f64,
    context: String,
    method: String,
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
        // Запись пути в лог
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .and_then(|mut f| {
                f.write_all(path.as_bytes())?;
                f.write_all(b"\n")
            });
    }
    let _ = method;
    s.findings.push(Finding {
        path,
        subcategory,
        value: take_first_chars(&value, 500),
        line_number,
        confidence,
        context: take_first_chars(&context, 500),
    });
}

fn scan_text(
    path: &str,
    log_path: &Path,
    text: &str,
    rules: &[Rule],
    prefilter: &Regex,
    shared: &Mutex<Shared>,
    _verbose: bool,
) {
    if prefilter.find(text).is_none() {
        return;
    }
    for rule in rules {
        for caps in rule.re.captures_iter(text) {
            let m = caps.get(1).or_else(|| caps.get(0));
            let Some(m) = m else { continue };
            let value = m.as_str();
            if value.chars().count() < 4 {
                continue;
            }
            if rule.entropy_check && shannon_entropy(value) < 3.0 {
                continue;
            }
            let line_num = line_number_at(text, m.start());
            let start = text.floor_char_boundary(m.start().saturating_sub(80));
            let end = text.floor_char_boundary((m.end() + 80).min(text.len()));
            let mut ctx = text[start..end].replace('\n', " ").trim().to_string();
            ctx = take_first_chars(&ctx, 500);
            add_finding(
                shared,
                path.to_string(),
                log_path,
                rule.subcategory.to_string(),
                value.to_string(),
                line_num,
                rule.confidence,
                ctx,
                "regex".to_string(),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

struct Args {
    folder: PathBuf,
    log: PathBuf,
    threads: usize,
    encoding: String,
    sniff: bool,
    verbose: bool,
}

fn usage() -> ! {
    eprintln!(
        "Использование: dcap-scan <папка> <лог-файл|папка> [потоков] [--no-sniff] [--encoding enc] [-v] [--presidio]"
    );
    std::process::exit(1);
}

fn parse_args() -> Args {
    let mut it = std::env::args().skip(1);
    let mut positionals: Vec<String> = Vec::new();
    let mut sniff = true;
    let mut verbose = false;
    let mut encoding = "utf-8".to_string();
    let mut threads_arg: Option<String> = None;

    while let Some(a) = it.next() {
        match a.as_str() {
            "--no-sniff" => sniff = false,
            "-v" | "--verbose" => verbose = true,
            "--presidio" => {
                eprintln!(
                    "[i] Presidio не поддерживается в Rust-версии, работает regex-режим"
                );
            }
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
    );

    println!();
    println!("{}", "=".repeat(60));
    println!("  Сканирование завершено");
    println!("  Папка:     {}", folder.display());
    println!(
        "  Файлов:    {} скан | {} пропуск | {} ошибки",
        out.files_scanned, out.files_skipped, 0,
    );
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