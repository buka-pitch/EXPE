use std::net::{Ipv4Addr, Ipv6Addr};

use expe_core::IpScope;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validated {
    pub value: String,
    pub scope: Option<IpScope>,
}

/// Validate and normalize a raw regex match. Returns `None` for false positives.
#[must_use]
pub fn validate(validator: &str, candidate: &str) -> Option<Validated> {
    let candidate = candidate.trim();
    if candidate.is_empty() {
        return None;
    }
    match validator {
        "ipv4" => validate_ipv4(candidate),
        "ipv6" => validate_ipv6(candidate),
        "domain" => validate_domain(candidate),
        "url" => validate_url(candidate),
        "email" => validate_email(candidate),
        "path" => validate_path(candidate),
        "bitcoin" => validate_bitcoin(candidate),
        "ethereum" => validate_ethereum(candidate),
        "onion" => validate_onion(candidate),
        "generic" => Some(Validated {
            value: trim_punctuation(candidate).to_string(),
            scope: None,
        }),
        _ => None,
    }
}

fn validate_ipv4(candidate: &str) -> Option<Validated> {
    let ip: Ipv4Addr = candidate.parse().ok()?;
    Some(Validated {
        value: ip.to_string(),
        scope: Some(ipv4_scope(ip)),
    })
}

fn validate_ipv6(candidate: &str) -> Option<Validated> {
    let candidate = candidate.split('%').next().unwrap_or(candidate);
    let ip: Ipv6Addr = candidate.parse().ok()?;
    Some(Validated {
        value: ip.to_string(),
        scope: Some(ipv6_scope(ip)),
    })
}

fn validate_domain(candidate: &str) -> Option<Validated> {
    let value = trim_punctuation(candidate)
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if value.len() < 4 || value.len() > 253 {
        return None;
    }
    if value.parse::<Ipv4Addr>().is_ok() || value.parse::<Ipv6Addr>().is_ok() {
        return None;
    }
    if value.contains("..") || value.starts_with('.') || !value.contains('.') {
        return None;
    }
    let labels: Vec<&str> = value.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return None;
        }
    }
    if labels
        .last()
        .is_some_and(|tld| tld.chars().all(|c| c.is_ascii_digit()))
    {
        return None;
    }
    if labels
        .last()
        .is_some_and(|tld| COMMON_FILE_EXTENSIONS.contains(tld))
    {
        return None;
    }
    Some(Validated { value, scope: None })
}

fn validate_url(candidate: &str) -> Option<Validated> {
    let trimmed = trim_punctuation(candidate);
    let url = Url::parse(trimmed).ok()?;
    if !matches!(url.scheme(), "http" | "https" | "ftp") {
        return None;
    }
    url.host_str()?;
    Some(Validated {
        value: trimmed.to_string(),
        scope: None,
    })
}

fn validate_email(candidate: &str) -> Option<Validated> {
    let value = trim_punctuation(candidate).to_ascii_lowercase();
    let (local, domain) = value.split_once('@')?;
    if local.is_empty() || local.len() > 64 {
        return None;
    }
    let domain = validate_domain(domain)?;
    Some(Validated {
        value: format!("{local}@{}", domain.value),
        scope: None,
    })
}

fn validate_path(candidate: &str) -> Option<Validated> {
    let value = trim_punctuation(candidate).to_string();
    if value.len() < 4 || value.len() > 512 {
        return None;
    }
    // Reject bare protocol-ish and obviously structural artifacts.
    if value.contains("://") || value.chars().all(|c| c == '.' || c == '/') {
        return None;
    }
    Some(Validated { value, scope: None })
}

fn validate_bitcoin(candidate: &str) -> Option<Validated> {
    let value = trim_punctuation(candidate);
    let plausible = (value.starts_with("bc1") && (42..=62).contains(&value.len()))
        || ((value.starts_with('1') || value.starts_with('3')) && (26..=35).contains(&value.len()));
    if !plausible
        || value
            .chars()
            .all(|c| c == value.chars().next().unwrap_or(' '))
    {
        return None;
    }
    Some(Validated {
        value: value.to_string(),
        scope: None,
    })
}

fn validate_ethereum(candidate: &str) -> Option<Validated> {
    let value = trim_punctuation(candidate);
    let hex = value.strip_prefix("0x")?;
    if hex.len() != 40 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    if hex.bytes().all(|b| b == b'0') {
        return None;
    }
    Some(Validated {
        value: value.to_ascii_lowercase(),
        scope: None,
    })
}

fn validate_onion(candidate: &str) -> Option<Validated> {
    let value = trim_punctuation(candidate).to_ascii_lowercase();
    let host = value.strip_suffix(".onion")?;
    if host.len() != 56
        || !host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
    {
        return None;
    }
    Some(Validated { value, scope: None })
}

/// Extensions that produce noisy "domain" false positives in binary strings.
const COMMON_FILE_EXTENSIONS: &[&str] = &[
    "exe", "dll", "sys", "drv", "ocx", "scr", "cpl", "msi", "msp", "bat", "cmd", "ps1", "vbs",
    "js", "jse", "wsf", "wsh", "hta", "jar", "class", "apk", "dex", "dylib", "o", "obj", "lib",
    "a", "txt", "log", "ini", "cfg", "conf", "json", "xml", "html", "htm", "css", "php", "asp",
    "aspx", "jsp", "py", "pyc", "rb", "pl", "sh", "bash", "zsh", "fish", "c", "h", "cpp", "hpp",
    "cs", "java", "rs", "go", "ts", "tsx", "jsx", "vue", "svelte", "md", "rst", "yml", "yaml",
    "toml", "lock", "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "webp", "tif", "tiff", "pdf",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "csv", "tsv", "zip", "rar", "7z", "gz",
    "bz2", "xz", "tar", "cab", "iso", "img", "vhd", "vmdk", "bin", "dat", "tmp", "db", "sqlite",
    "mdb", "pem", "crt", "cer", "key", "p12", "pfx", "woff", "woff2", "ttf", "otf", "eot", "mp3",
    "mp4", "avi", "mkv", "mov", "wav", "wmv", "flac", "elf", "macho", "wasm", "ko", "manifest",
    "config", "cache", "pid", "sock", "pid",
];

fn trim_punctuation(value: &str) -> &str {
    value.trim_end_matches(['.', ',', ';', ':', '!', '?', ')', ']', '}', '\'', '"'])
}

#[must_use]
pub fn ipv4_scope(ip: Ipv4Addr) -> IpScope {
    let octets = ip.octets();
    if ip.is_loopback() {
        IpScope::Loopback
    } else if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() {
        IpScope::Reserved
    } else if ip.is_private() {
        IpScope::Private
    } else if ip.is_link_local() {
        IpScope::LinkLocal
    } else if octets[0] == 0
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        || octets[0] >= 240
    {
        IpScope::Reserved
    } else {
        IpScope::Public
    }
}

#[must_use]
pub fn ipv6_scope(ip: Ipv6Addr) -> IpScope {
    if ip.is_loopback() {
        IpScope::Loopback
    } else if ip.is_unspecified() || ip.is_multicast() {
        IpScope::Reserved
    } else if ip.is_unique_local() {
        IpScope::Private
    } else if ip.is_unicast_link_local() {
        IpScope::LinkLocal
    } else {
        IpScope::Public
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_valid_and_scope() {
        assert_eq!(
            validate("ipv4", "185.1.2.3").unwrap().scope,
            Some(IpScope::Public)
        );
        assert_eq!(
            validate("ipv4", "192.168.1.1").unwrap().scope,
            Some(IpScope::Private)
        );
        assert_eq!(
            validate("ipv4", "127.0.0.1").unwrap().scope,
            Some(IpScope::Loopback)
        );
        assert_eq!(
            validate("ipv4", "192.0.2.5").unwrap().scope,
            Some(IpScope::Reserved)
        );
        assert!(validate("ipv4", "999.1.2.3").is_none());
        assert!(validate("ipv4", "1.2.3").is_none());
    }

    #[test]
    fn ipv6_valid() {
        let result = validate("ipv6", "2001:db8::1").unwrap();
        assert_eq!(result.value, "2001:db8::1");
        assert!(validate("ipv6", "::1").is_some());
        assert!(validate("ipv6", "nope").is_none());
    }

    #[test]
    fn domain_filters() {
        assert_eq!(
            validate("domain", "Evil.Example.COM").unwrap().value,
            "evil.example.com"
        );
        assert!(validate("domain", "kernel32.dll").is_none());
        assert!(validate("domain", "1.2.3.4").is_none());
        assert!(validate("domain", "a..b.com").is_none());
        assert!(validate("domain", "-bad.com").is_none());
    }

    #[test]
    fn url_trims_punctuation() {
        let result = validate("url", "http://evil.test/path).").unwrap();
        assert_eq!(result.value, "http://evil.test/path");
        assert!(validate("url", "javascript:alert(1)").is_none());
    }

    #[test]
    fn email_and_paths() {
        assert_eq!(
            validate("email", "analyst@Example.COM").unwrap().value,
            "analyst@example.com"
        );
        assert!(validate("email", "not-an-email").is_none());
        assert!(validate("path", "C:\\Users\\dev\\a.pdb").is_some());
        assert!(validate("path", "/etc/passwd").is_some());
        assert!(validate("path", "....").is_none());
    }

    #[test]
    fn wallets() {
        assert!(validate("bitcoin", "1BoatSLRHtKNngkdXEeobR76b53LETtpyT").is_some());
        assert!(validate("bitcoin", "not-a-wallet").is_none());
        assert!(validate("ethereum", "0x52908400098527886E0F7030069857D2E4169EE7").is_some());
        assert!(validate("ethereum", "0x0").is_none());
        assert!(
            validate(
                "onion",
                "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567.onion"
            )
            .is_none()
        );
    }
}
