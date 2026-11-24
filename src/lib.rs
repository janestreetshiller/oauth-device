//! OAuth 2.0 device authorization for desktop and CLI programs.
//!
//! The device flow is the only OAuth grant that needs no browser redirect, no
//! client secret and no localhost listener: the program asks the provider for a
//! short code, the user types it on the provider's page, and the program polls
//! until the token appears.
//!
//! ```no_run
//! use oauth_device::{provider, FileStore, Poll};
//!
//! let github = provider("github").unwrap();
//! let client_id = std::env::var("GITHUB_CLIENT_ID").unwrap();
//! let device = oauth_device::request_device_code(github, &client_id)?;
//! println!("Open {} and enter {}", device.verification_uri, device.user_code);
//! loop {
//!     std::thread::sleep(std::time::Duration::from_secs(device.interval));
//!     match oauth_device::poll_token(github, &client_id, &device.device_code)? {
//!         Poll::Pending => continue,
//!         Poll::Token { token } => {
//!             let login = oauth_device::identity(github, &token)?;
//!             FileStore::new("connections.tsv").save(github.id, &token, &login)?;
//!             break;
//!         }
//!         Poll::Failure(message) => panic!("{message}"),
//!         Poll::SlowDown => continue,
//!     }
//! }
//! # Ok::<(), String>(())
//! ```

use serde_json::Value;
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

const USER_AGENT: &str = "oauth-device";

/// A provider that speaks the device grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Provider {
    pub id: &'static str,
    pub name: &'static str,
    pub scope: &'static str,
    pub device_url: &'static str,
    pub token_url: &'static str,
    pub identity_url: &'static str,
}

/// GitHub: device endpoints take a client id only, so no secret ships in the app.
pub const GITHUB: Provider = Provider {
    id: "github",
    name: "GitHub",
    scope: "repo read:user",
    device_url: "https://github.com/login/device/code",
    token_url: "https://github.com/login/oauth/access_token",
    identity_url: "https://api.github.com/user",
};

/// Google: the OAuth client must be created with the TV and limited-input type.
pub const GOOGLE: Provider = Provider {
    id: "google",
    name: "Google",
    scope: "openid email https://www.googleapis.com/auth/calendar.readonly",
    device_url: "https://oauth2.googleapis.com/device/code",
    token_url: "https://oauth2.googleapis.com/token",
    identity_url: "https://openidconnect.googleapis.com/v1/userinfo",
};

pub static PROVIDERS: [Provider; 2] = [GITHUB, GOOGLE];

pub fn provider(id: &str) -> Option<&'static Provider> {
    PROVIDERS.iter().find(|p| p.id == id)
}

/// Test hook: route every request at `base` instead of the provider.
const BASE_ENV: &str = "OAUTH_DEVICE_BASE";

fn endpoint(real: &str) -> String {
    match std::env::var(BASE_ENV) {
        Ok(base) => {
            let path = real
                .splitn(4, '/')
                .nth(3)
                .map(|rest| format!("/{rest}"))
                .unwrap_or_default();
            format!("{}{path}", base.trim_end_matches('/'))
        }
        Err(_) => real.to_string(),
    }
}

/// One pending authorization, as handed out by the provider.
#[derive(Debug, Clone)]
pub struct DeviceCode {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub interval: u64,
    pub expires_in: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Poll {
    Pending,
    SlowDown,
    Token { token: String },
    Failure(String),
}

fn post(url: &str, form: &[(&str, &str)]) -> Result<(u16, Value), String> {
    let response = ureq::post(url)
        .set("accept", "application/json")
        .set("user-agent", USER_AGENT)
        .timeout(Duration::from_secs(20))
        .send_form(form);
    match response {
        Ok(r) => {
            let status = r.status();
            let body = r.into_string().map_err(|e| e.to_string())?;
            Ok((status, serde_json::from_str(&body).unwrap_or(Value::Null)))
        }
        Err(ureq::Error::Status(status, r)) => {
            let body = r.into_string().unwrap_or_default();
            Ok((status, serde_json::from_str(&body).unwrap_or(Value::Null)))
        }
        Err(ureq::Error::Transport(t)) => Err(t.to_string()),
    }
}

fn get(url: &str, token: &str) -> Result<Value, String> {
    let response = ureq::get(url)
        .set("accept", "application/json")
        .set("user-agent", USER_AGENT)
        .set("authorization", &format!("Bearer {token}"))
        .timeout(Duration::from_secs(20))
        .call();
    match response {
        Ok(r) => {
            let body = r.into_string().map_err(|e| e.to_string())?;
            Ok(serde_json::from_str(&body).unwrap_or(Value::Null))
        }
        Err(ureq::Error::Status(status, r)) => {
            let body = r.into_string().unwrap_or_default();
            Err(format!("identity request failed ({status}): {body}"))
        }
        Err(ureq::Error::Transport(t)) => Err(t.to_string()),
    }
}

pub fn request_device_code(p: &Provider, client_id: &str) -> Result<DeviceCode, String> {
    let (status, body) = post(
        &endpoint(p.device_url),
        &[("client_id", client_id), ("scope", p.scope)],
    )?;
    if status >= 400 {
        return Err(describe_error(&body, status));
    }
    Ok(DeviceCode {
        device_code: string_field(&body, "device_code")
            .ok_or_else(|| "device response had no device_code".to_string())?,
        user_code: string_field(&body, "user_code")
            .ok_or_else(|| "device response had no user_code".to_string())?,
        verification_uri: string_field(&body, "verification_uri")
            .or_else(|| string_field(&body, "verification_url"))
            .ok_or_else(|| "device response had no verification_uri".to_string())?,
        interval: body.get("interval").and_then(Value::as_u64).unwrap_or(5),
        expires_in: body.get("expires_in").and_then(Value::as_u64).unwrap_or(900),
    })
}

pub fn poll_token(p: &Provider, client_id: &str, device_code: &str) -> Result<Poll, String> {
    let (status, body) = post(
        &endpoint(p.token_url),
        &[
            ("client_id", client_id),
            ("device_code", device_code),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ],
    )?;
    if let Some(token) = string_field(&body, "access_token") {
        return Ok(Poll::Token { token });
    }
    match body.get("error").and_then(Value::as_str) {
        Some("authorization_pending") => Ok(Poll::Pending),
        Some("slow_down") => Ok(Poll::SlowDown),
        Some("expired_token") | Some("code_expired") => {
            Ok(Poll::Failure("The code expired before it was approved.".into()))
        }
        Some("access_denied") => Ok(Poll::Failure("Authorization was denied.".into())),
        Some(other) => Ok(Poll::Failure(format!("Authorization failed: {other}"))),
        None if status >= 400 => Err(describe_error(&body, status)),
        None => Ok(Poll::Pending),
    }
}

pub fn identity(p: &Provider, token: &str) -> Result<String, String> {
    let body = get(&endpoint(p.identity_url), token)?;
    string_field(&body, "login")
        .or_else(|| string_field(&body, "email"))
        .or_else(|| string_field(&body, "name"))
        .ok_or_else(|| "identity response had no login or email".to_string())
}

fn describe_error(body: &Value, status: u16) -> String {
    let detail = string_field(body, "error_description")
        .or_else(|| string_field(body, "message"))
        .or_else(|| string_field(body, "error"));
    match detail {
        Some(d) => format!("OAuth request failed ({status}): {d}"),
        None => format!("OAuth request failed ({status})."),
    }
}

fn string_field(body: &Value, key: &str) -> Option<String> {
    body.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Connection {
    pub provider: String,
    pub token: String,
    pub login: String,
    pub obtained: u64,
}

/// Tokens in one tab-separated file, restricted to the owner on Unix.
pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    pub fn new(path: impl AsRef<Path>) -> Self {
        FileStore {
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load_all(&self) -> BTreeMap<String, Connection> {
        let mut out = BTreeMap::new();
        let Ok(raw) = std::fs::read_to_string(&self.path) else {
            return out;
        };
        for line in raw.lines() {
            let mut fields = line.split('\t');
            if fields.next() != Some("oauth") {
                continue;
            }
            let (Some(provider), Some(token), Some(login)) =
                (fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            if token.is_empty() {
                continue;
            }
            let obtained = fields.next().and_then(|v| v.parse().ok()).unwrap_or(0);
            out.insert(
                provider.to_string(),
                Connection {
                    provider: provider.to_string(),
                    token: token.to_string(),
                    login: login.to_string(),
                    obtained,
                },
            );
        }
        out
    }

    pub fn save(&self, provider: &str, token: &str, login: &str) -> Result<(), String> {
        let mut all = self.load_all();
        all.insert(
            provider.to_string(),
            Connection {
                provider: provider.to_string(),
                token: token.to_string(),
                login: login.to_string(),
                obtained: now_unix(),
            },
        );
        let mut body = String::new();
        for c in all.values() {
            body.push_str(&format!(
                "oauth\t{}\t{}\t{}\t{}\n",
                c.provider, c.token, c.login, c.obtained
            ));
        }
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(io_error)?;
            }
        }
        std::fs::write(&self.path, body).map_err(io_error)?;
        restrict(&self.path);
        Ok(())
    }

    pub fn remove(&self, provider: &str) -> Result<(), String> {
        let mut all = self.load_all();
        all.remove(provider);
        let mut body = String::new();
        for c in all.values() {
            body.push_str(&format!(
                "oauth\t{}\t{}\t{}\t{}\n",
                c.provider, c.token, c.login, c.obtained
            ));
        }
        std::fs::write(&self.path, body).map_err(io_error)?;
        restrict(&self.path);
        Ok(())
    }
}

fn io_error(e: io::Error) -> String {
    e.to_string()
}

#[cfg(unix)]
fn restrict(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
fn restrict(_: &Path) {}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn serve(responses: Vec<(u16, String)>) -> (String, std::thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for (code, body) in responses {
                let (stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();
                let mut length = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap() == 0 {
                        break;
                    }
                    if line == "\r\n" || line == "\n" {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body_in = vec![0u8; length];
                if length > 0 {
                    reader.read_exact(&mut body_in).unwrap();
                }
                seen.push(format!(
                    "{} {}",
                    request_line.trim_end(),
                    String::from_utf8_lossy(&body_in)
                ));
                let mut stream = stream;
                let response = format!(
                    "HTTP/1.1 {code} OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
                stream.flush().unwrap();
            }
            seen
        });
        (format!("http://{addr}"), handle)
    }

    #[test]
    fn polls_until_the_token_arrives() {
        let _guard = ENV_LOCK.lock().unwrap();
        let (base, handle) = serve(vec![
            (200, r#"{"device_code":"dev-1","user_code":"ABCD-1234","verification_uri":"https://github.com/login/device","expires_in":900,"interval":1}"#.to_string()),
            (200, r#"{"error":"authorization_pending"}"#.to_string()),
            (200, r#"{"access_token":"tok-42"}"#.to_string()),
        ]);
        std::env::set_var(BASE_ENV, &base);
        let device = request_device_code(&GITHUB, "client-1").unwrap();
        assert_eq!(device.user_code, "ABCD-1234");
        assert_eq!(
            poll_token(&GITHUB, "client-1", &device.device_code).unwrap(),
            Poll::Pending
        );
        assert_eq!(
            poll_token(&GITHUB, "client-1", &device.device_code).unwrap(),
            Poll::Token {
                token: "tok-42".into()
            }
        );
        std::env::remove_var(BASE_ENV);
        let seen = handle.join().unwrap();
        assert!(seen[0].starts_with("POST /login/device/code"));
        assert!(seen[2].contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"));
    }

    #[test]
    fn slow_down_and_denial_are_distinct() {
        let _guard = ENV_LOCK.lock().unwrap();
        let (base, handle) = serve(vec![
            (200, r#"{"error":"slow_down"}"#.to_string()),
            (200, r#"{"error":"access_denied"}"#.to_string()),
        ]);
        std::env::set_var(BASE_ENV, &base);
        assert_eq!(poll_token(&GOOGLE, "c", "d").unwrap(), Poll::SlowDown);
        match poll_token(&GOOGLE, "c", "d").unwrap() {
            Poll::Failure(message) => assert!(message.contains("denied")),
            other => panic!("expected failure, got {other:?}"),
        }
        std::env::remove_var(BASE_ENV);
        let _ = handle.join().unwrap();
    }

    #[test]
    fn identity_reads_the_login() {
        let _guard = ENV_LOCK.lock().unwrap();
        let (base, handle) = serve(vec![(200, r#"{"login":"octocat"}"#.to_string())]);
        std::env::set_var(BASE_ENV, &base);
        assert_eq!(identity(&GITHUB, "tok").unwrap(), "octocat");
        std::env::remove_var(BASE_ENV);
        let seen = handle.join().unwrap();
        assert!(seen[0].starts_with("GET /user"));
    }

    #[test]
    fn provider_errors_survive_with_their_status() {
        let _guard = ENV_LOCK.lock().unwrap();
        let (base, handle) = serve(vec![(
            404,
            r#"{"message":"Not Found","error_description":"unknown client"}"#.to_string(),
        )]);
        std::env::set_var(BASE_ENV, &base);
        let err = request_device_code(&GITHUB, "bad").unwrap_err();
        std::env::remove_var(BASE_ENV);
        let _ = handle.join().unwrap();
        assert!(err.contains("404"));
        assert!(err.contains("unknown client"));
    }

    #[test]
    fn store_round_trips_and_restricts_the_file() {
        let dir = std::env::temp_dir().join(format!("oauth-device-{}", std::process::id()));
        let store = FileStore::new(dir.join("connections.tsv"));
        store.save("github", "tok", "octocat").unwrap();
        let all = store.load_all();
        assert_eq!(all["github"].login, "octocat");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(store.path()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        store.remove("github").unwrap();
        assert!(store.load_all().is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }
}
