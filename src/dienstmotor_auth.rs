//! Dienstmotor Remote: operator sign-in (Authentik OIDC, Authorization Code + PKCE S256 over a
//! loopback redirect) and connection tickets.
//!
//! * Controller side: every new connection (`Client::start`) first obtains a short-lived ticket
//!   from the auth API. It goes to hbbs in the rendezvous `token` field and to the host inside
//!   the end-to-end encrypted `LoginRequest`.
//! * Host side: a login is accepted only with a valid ticket for this device, checked once per
//!   connection. Nothing is re-checked afterwards, so token expiry, logout or revocation never
//!   touch an established session; a reconnect is a new connection and needs a new ticket.

use crate::{branding, client::Interface};
use hbb_common::{
    anyhow::anyhow,
    base64::{
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
        Engine as _,
    },
    bail,
    config::Config,
    log,
    rendezvous_proto::ConnType,
    sodiumoxide::{
        self,
        crypto::sign::{verify_detached, PublicKey, Signature},
        randombytes::randombytes,
    },
    tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::Mutex as TokioMutex,
    },
    ResultType,
};
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const TICKET_AUDIENCE: &str = "dienstmotor-remote";
const HOST_CLOCK_LEEWAY: i64 = 300;
const LOGIN_TIMEOUT: Duration = Duration::from_secs(300);
const REFRESH_MARGIN: i64 = 30;
const STORE_FILE: &str = "dienstmotor_auth.dat";

pub const MSG_LOGIN_REQUIRED: &str = "Dienstmotor: sign in to start a connection";
pub const MSG_SESSION_EXPIRED: &str = "Dienstmotor: your session expired, sign in again";
pub const MSG_UNAVAILABLE: &str = "Dienstmotor: authorization service unavailable, try again later";
const MSG_DIRECT_DISABLED: &str =
    "Dienstmotor: only connections by device ID through the Dienstmotor server are allowed";
const MSG_HOST_REFUSED: &str =
    "Dienstmotor: this device only accepts connections from signed-in Dienstmotor operators";

#[derive(Serialize, Deserialize, Default, Clone)]
struct Tokens {
    access_token: String,
    refresh_token: String,
    expires_at: i64,
    token_endpoint: String,
    revocation_endpoint: String,
    client_id: String,
    username: String,
    name: String,
}

#[derive(Default)]
struct UiState {
    authenticating: bool,
    error: String,
}

lazy_static::lazy_static! {
    static ref TOKENS: Mutex<Option<Tokens>> = Mutex::new(load_tokens());
    static ref UI: Mutex<UiState> = Default::default();
    static ref REFRESH_LOCK: TokioMutex<()> = TokioMutex::new(());
    static ref USED_TICKETS: Mutex<HashMap<String, (i32, i64)>> = Default::default();
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

fn api(path: &str) -> String {
    format!("{}{}", branding::AUTH_API_URL, path)
}

// ---------------------------------------------------------------------------------------------
// Status for the UI

/// JSON: `{"state": "unauthenticated" | "authenticating" | "authenticated", "username", "name", "error"}`.
pub fn status() -> String {
    let ui = UI.lock().unwrap();
    let tokens = TOKENS.lock().unwrap();
    let state = if ui.authenticating {
        "authenticating"
    } else if tokens.is_some() {
        "authenticated"
    } else {
        "unauthenticated"
    };
    let (username, name) = tokens
        .as_ref()
        .map(|t| (t.username.clone(), t.name.clone()))
        .unwrap_or_default();
    serde_json::json!({
        "state": state,
        "username": username,
        "name": name,
        "error": ui.error,
    })
    .to_string()
}

fn set_error(err: &str) {
    let mut ui = UI.lock().unwrap();
    ui.authenticating = false;
    ui.error = err.to_owned();
}

// ---------------------------------------------------------------------------------------------
// Token storage: DPAPI (current user) on Windows, a 0600 file elsewhere.

fn load_tokens() -> Option<Tokens> {
    let data = std::fs::read(Config::path(STORE_FILE)).ok()?;
    let data = unprotect(&data)
        .map_err(|e| log::warn!("Dienstmotor auth: cannot read stored session: {e}"))
        .ok()?;
    serde_json::from_slice(&data).ok()
}

fn save_tokens(tokens: Option<Tokens>) {
    let path = Config::path(STORE_FILE);
    match tokens.as_ref() {
        Some(t) => {
            let res = serde_json::to_vec(t)
                .map_err(|e| anyhow!(e))
                .and_then(|data| protect(&data))
                .and_then(|data| write_private(&path, &data));
            if let Err(e) = res {
                log::error!("Dienstmotor auth: cannot store session: {e}");
            }
        }
        None => {
            if path.exists() {
                if let Err(e) = std::fs::remove_file(&path) {
                    log::error!("Dienstmotor auth: cannot remove stored session: {e}");
                }
            }
        }
    }
    *TOKENS.lock().unwrap() = tokens;
}

#[cfg(not(windows))]
fn write_private(path: &std::path::Path, data: &[u8]) -> ResultType<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

#[cfg(windows)]
fn write_private(path: &std::path::Path, data: &[u8]) -> ResultType<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, data)?;
    Ok(())
}

#[cfg(not(windows))]
fn protect(data: &[u8]) -> ResultType<Vec<u8>> {
    Ok(data.to_vec())
}

#[cfg(not(windows))]
fn unprotect(data: &[u8]) -> ResultType<Vec<u8>> {
    Ok(data.to_vec())
}

#[cfg(windows)]
fn protect(data: &[u8]) -> ResultType<Vec<u8>> {
    dpapi(data, true)
}

#[cfg(windows)]
fn unprotect(data: &[u8]) -> ResultType<Vec<u8>> {
    dpapi(data, false)
}

#[cfg(windows)]
fn dpapi(data: &[u8], encrypt: bool) -> ResultType<Vec<u8>> {
    use winapi::um::{
        dpapi::{CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN},
        winbase::LocalFree,
        wincrypt::DATA_BLOB,
    };
    let mut input = DATA_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output = DATA_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        if encrypt {
            CryptProtectData(
                &mut input,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &mut input,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };
    if ok == 0 || output.pbData.is_null() {
        bail!("DPAPI failed: {}", std::io::Error::last_os_error());
    }
    let out = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe { LocalFree(output.pbData as _) };
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// HTTP helpers

async fn http_client(url: &str) -> ResultType<reqwest::Client> {
    crate::hbbs_http::create_http_client_async_with_url_strict(url).await
}

async fn get_json(url: &str, bearer: Option<&str>) -> ResultType<(u16, serde_json::Value)> {
    let mut req = http_client(url).await?.get(url).timeout(Duration::from_secs(15));
    if let Some(b) = bearer {
        req = req.bearer_auth(b);
    }
    let resp = req.send().await?;
    let status = resp.status().as_u16();
    Ok((status, resp.json().await.unwrap_or(serde_json::Value::Null)))
}

async fn post_form(url: &str, form: &[(&str, &str)]) -> ResultType<(u16, serde_json::Value)> {
    let resp = http_client(url)
        .await?
        .post(url)
        .timeout(Duration::from_secs(15))
        .form(form)
        .send()
        .await?;
    let status = resp.status().as_u16();
    Ok((status, resp.json().await.unwrap_or(serde_json::Value::Null)))
}

fn str_field(v: &serde_json::Value, key: &str) -> String {
    v.get(key).and_then(|x| x.as_str()).unwrap_or_default().to_owned()
}

// ---------------------------------------------------------------------------------------------
// Login (Authorization Code + PKCE S256, loopback redirect, RFC 8252)

fn random_b64(n: usize) -> String {
    URL_SAFE_NO_PAD.encode(randombytes(n))
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn percent(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// Parses the browser's request to the loopback listener. Returns the authorization code
/// when the request is the callback for `expected_state`.
fn parse_callback(request: &str, expected_state: &str) -> Option<Result<String, String>> {
    let target = request.lines().next()?.strip_prefix("GET ")?.split(' ').next()?;
    let url = url::Url::parse(&format!("http://127.0.0.1{target}")).ok()?;
    if url.path() != "/callback" {
        return None;
    }
    let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
    if params.get("state").map(|s| s.as_str()) != Some(expected_state) {
        return Some(Err("state mismatch".to_owned()));
    }
    if let Some(err) = params.get("error") {
        return Some(Err(err.clone()));
    }
    params
        .get("code")
        .filter(|c| !c.is_empty())
        .map(|c| Ok(c.clone()))
        .or(Some(Err("missing authorization code".to_owned())))
}

/// Checks the ID token returned by the token endpoint. It came straight from the issuer over
/// TLS, so (OIDC Core 3.1.3.7) the claims are checked without verifying the signature here; the
/// auth API independently verifies the access token's signature on every request.
fn check_id_token(id_token: &str, issuer: &str, client_id: &str, nonce: &str) -> Result<(), String> {
    let payload = id_token.split('.').nth(1).ok_or("malformed id_token")?;
    let claims: serde_json::Value = URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or("malformed id_token")?;
    if str_field(&claims, "nonce") != nonce {
        return Err("nonce mismatch".to_owned());
    }
    if str_field(&claims, "iss").trim_end_matches('/') != issuer.trim_end_matches('/') {
        return Err("issuer mismatch".to_owned());
    }
    let aud_ok = match claims.get("aud") {
        Some(serde_json::Value::String(a)) => a == client_id,
        Some(serde_json::Value::Array(a)) => a.iter().any(|x| x.as_str() == Some(client_id)),
        _ => false,
    };
    if !aud_ok {
        return Err("audience mismatch".to_owned());
    }
    Ok(())
}

/// Starts the browser sign-in. Returns the authorization URL the UI must open, or an error.
/// The rest of the flow continues in the background; poll [`status`].
pub fn start_login() -> Result<String, String> {
    {
        let mut ui = UI.lock().unwrap();
        if ui.authenticating {
            return Err("sign-in already in progress".to_owned());
        }
        ui.authenticating = true;
        ui.error.clear();
    }
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        if let Err(e) = run_login(tx) {
            log::warn!("Dienstmotor sign-in failed: {e}");
            set_error(&e.to_string());
        }
    });
    match rx.recv_timeout(Duration::from_secs(30)) {
        Ok(url) => Ok(url),
        Err(_) => {
            let err = UI.lock().unwrap().error.clone();
            Err(if err.is_empty() { MSG_UNAVAILABLE.to_owned() } else { err })
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn run_login(url_tx: std::sync::mpsc::Sender<String>) -> ResultType<()> {
    let (status, cfg) = get_json(&api("/auth/config"), None).await?;
    let issuer = str_field(&cfg, "issuer");
    let client_id = str_field(&cfg, "client_id");
    let scopes = str_field(&cfg, "scopes");
    if status != 200 || issuer.is_empty() || client_id.is_empty() {
        bail!(MSG_UNAVAILABLE);
    }
    let discovery_url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
    let (status, doc) = get_json(&discovery_url, None).await?;
    if status != 200 || str_field(&doc, "issuer").trim_end_matches('/') != issuer.trim_end_matches('/') {
        bail!("OIDC discovery failed");
    }
    let authorization_endpoint = str_field(&doc, "authorization_endpoint");
    let token_endpoint = str_field(&doc, "token_endpoint");
    if !authorization_endpoint.starts_with("https://") || !token_endpoint.starts_with("https://") {
        bail!("OIDC discovery returned insecure endpoints");
    }

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let redirect_uri = format!("http://127.0.0.1:{}/callback", listener.local_addr()?.port());
    let verifier = random_b64(32);
    let state = random_b64(16);
    let nonce = random_b64(16);
    let auth_url = format!(
        "{authorization_endpoint}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
        percent(&client_id),
        percent(&redirect_uri),
        percent(&scopes),
        percent(&state),
        percent(&nonce),
        percent(&pkce_challenge(&verifier)),
    );
    url_tx.send(auth_url).ok();

    let code = tokio::time::timeout(LOGIN_TIMEOUT, wait_for_callback(&listener, &state))
        .await
        .map_err(|_| anyhow!("sign-in timed out"))??;
    drop(listener);

    let (status, tok) = post_form(
        &token_endpoint,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &redirect_uri),
            ("client_id", &client_id),
            ("code_verifier", &verifier),
        ],
    )
    .await?;
    if status != 200 {
        bail!("token exchange failed ({status})");
    }
    check_id_token(&str_field(&tok, "id_token"), &issuer, &client_id, &nonce)
        .map_err(|e| anyhow!("invalid ID token: {e}"))?;
    let mut tokens = Tokens {
        access_token: str_field(&tok, "access_token"),
        refresh_token: str_field(&tok, "refresh_token"),
        expires_at: now() + tok.get("expires_in").and_then(|v| v.as_i64()).unwrap_or(300),
        token_endpoint,
        revocation_endpoint: str_field(&doc, "revocation_endpoint"),
        client_id,
        ..Default::default()
    };
    if tokens.access_token.is_empty() {
        bail!("token exchange returned no access token");
    }
    let (status, me) = get_json(&api("/auth/me"), Some(&tokens.access_token)).await?;
    if status != 200 {
        bail!("Dienstmotor rejected the sign-in ({status})");
    }
    tokens.username = str_field(&me, "username");
    tokens.name = str_field(&me, "name");
    save_tokens(Some(tokens));
    let mut ui = UI.lock().unwrap();
    ui.authenticating = false;
    ui.error.clear();
    Ok(())
}

async fn wait_for_callback(listener: &TcpListener, state: &str) -> ResultType<String> {
    loop {
        let (mut stream, _) = listener.accept().await?;
        let mut buf = vec![0u8; 8192];
        let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf))
            .await
            .unwrap_or(Ok(0))
            .unwrap_or(0);
        let request = String::from_utf8_lossy(&buf[..n]);
        let Some(result) = parse_callback(&request, state) else {
            stream
                .write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                .await
                .ok();
            continue;
        };
        let body = match &result {
            Ok(_) => "<h2>Dienstmotor Remote</h2><p>Sesi&oacute;n iniciada. Puedes cerrar esta ventana y volver a la aplicaci&oacute;n.</p>",
            Err(_) => "<h2>Dienstmotor Remote</h2><p>No se pudo iniciar sesi&oacute;n. Vuelve a la aplicaci&oacute;n e int&eacute;ntalo de nuevo.</p>",
        };
        let page = format!(
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>Dienstmotor Remote</title></head><body style=\"font-family:sans-serif;text-align:center;margin-top:15%\">{body}</body></html>"
        );
        let resp = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/html; charset=utf-8\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{page}",
            page.len()
        );
        stream.write_all(resp.as_bytes()).await.ok();
        stream.shutdown().await.ok();
        return result.map_err(|e| anyhow!("authorization failed: {e}"));
    }
}

// ---------------------------------------------------------------------------------------------
// Logout

pub fn logout() {
    let Some(tokens) = TOKENS.lock().unwrap().clone() else {
        return;
    };
    save_tokens(None);
    set_error("");
    std::thread::spawn(move || revoke(tokens));
}

#[tokio::main(flavor = "current_thread")]
async fn revoke(tokens: Tokens) {
    if !tokens.revocation_endpoint.starts_with("https://") {
        return;
    }
    for (token, hint) in [
        (&tokens.refresh_token, "refresh_token"),
        (&tokens.access_token, "access_token"),
    ] {
        if token.is_empty() {
            continue;
        }
        let form = [
            ("token", token.as_str()),
            ("token_type_hint", hint),
            ("client_id", tokens.client_id.as_str()),
        ];
        if let Err(e) = post_form(&tokens.revocation_endpoint, &form).await {
            log::warn!("Dienstmotor auth: token revocation failed: {e}");
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Controller side: a fresh ticket for each new connection

enum Refresh {
    Ok,
    Rejected,
    Unavailable,
}

async fn refresh(current_access_token: &str) -> Refresh {
    let _guard = REFRESH_LOCK.lock().await;
    let Some(tokens) = TOKENS.lock().unwrap().clone() else {
        return Refresh::Rejected;
    };
    if tokens.access_token != current_access_token && tokens.expires_at - REFRESH_MARGIN > now() {
        return Refresh::Ok; // another connection refreshed meanwhile
    }
    if tokens.refresh_token.is_empty() {
        return Refresh::Rejected;
    }
    let form = [
        ("grant_type", "refresh_token"),
        ("refresh_token", tokens.refresh_token.as_str()),
        ("client_id", tokens.client_id.as_str()),
    ];
    match post_form(&tokens.token_endpoint, &form).await {
        Ok((200, tok)) if !str_field(&tok, "access_token").is_empty() => {
            let refresh_token = str_field(&tok, "refresh_token");
            save_tokens(Some(Tokens {
                access_token: str_field(&tok, "access_token"),
                refresh_token: if refresh_token.is_empty() {
                    tokens.refresh_token.clone()
                } else {
                    refresh_token
                },
                expires_at: now() + tok.get("expires_in").and_then(|v| v.as_i64()).unwrap_or(300),
                ..tokens
            }));
            Refresh::Ok
        }
        Ok((status, _)) if (400..500).contains(&status) => Refresh::Rejected,
        Ok(_) | Err(_) => Refresh::Unavailable,
    }
}

fn expire_session() {
    save_tokens(None);
    set_error(MSG_SESSION_EXPIRED);
}

/// A rendezvous `token` used to mean a Pro access token, which makes the client wait for the
/// server's key exchange. OSS hbbs never sends one, so a Dienstmotor ticket must not trigger it.
pub fn wants_secure_tcp(token: &str) -> bool {
    !token.is_empty() && !token.starts_with("dm1.")
}

fn conn_type_name(conn_type: ConnType) -> &'static str {
    match conn_type {
        ConnType::FILE_TRANSFER => "file_transfer",
        ConnType::PORT_FORWARD => "port_forward",
        ConnType::RDP => "rdp",
        ConnType::VIEW_CAMERA => "view_camera",
        ConnType::TERMINAL => "terminal",
        _ => "default",
    }
}

/// Obtains the ticket for a new connection to `peer` and attaches it to the session's login
/// request. Fails (and so refuses the connection) when the operator is not signed in, the
/// session cannot be renewed, or the auth API is unreachable.
pub async fn connection_ticket(
    peer: &str,
    conn_type: ConnType,
    interface: &impl Interface,
) -> ResultType<String> {
    if hbb_common::is_ip_str(peer)
        || hbb_common::is_domain_port_str(peer)
        || interface.get_lch().read().unwrap().other_server.is_some()
    {
        bail!(MSG_DIRECT_DISABLED);
    }
    let ticket = fetch_ticket(peer, conn_type_name(conn_type)).await?;
    interface.get_lch().write().unwrap().dm_ticket = ticket.clone();
    Ok(ticket)
}

async fn fetch_ticket(peer: &str, conn_type: &str) -> ResultType<String> {
    let body = serde_json::json!({ "peer_id": peer, "conn_type": conn_type }).to_string();
    for attempt in 0..2 {
        let Some(tokens) = TOKENS.lock().unwrap().clone() else {
            bail!(MSG_LOGIN_REQUIRED);
        };
        if attempt == 0 && tokens.expires_at - REFRESH_MARGIN <= now() {
            match refresh(&tokens.access_token).await {
                Refresh::Ok => continue,
                Refresh::Rejected => {
                    expire_session();
                    bail!(MSG_SESSION_EXPIRED);
                }
                Refresh::Unavailable => bail!(MSG_UNAVAILABLE),
            }
        }
        let url = api("/auth/ticket");
        let resp = http_client(&url)
            .await?
            .post(&url)
            .timeout(Duration::from_secs(10))
            .bearer_auth(&tokens.access_token)
            .header("content-type", "application/json")
            .body(body.clone())
            .send()
            .await
            .map_err(|e| {
                log::warn!("Dienstmotor auth: ticket request failed: {e}");
                anyhow!(MSG_UNAVAILABLE)
            })?;
        match resp.status().as_u16() {
            200 => {
                let v: serde_json::Value = resp.json().await.map_err(|_| anyhow!(MSG_UNAVAILABLE))?;
                let ticket = str_field(&v, "ticket");
                if ticket.is_empty() {
                    bail!(MSG_UNAVAILABLE);
                }
                return Ok(ticket);
            }
            401 if attempt == 0 => match refresh(&tokens.access_token).await {
                Refresh::Ok => continue,
                Refresh::Rejected => {
                    expire_session();
                    bail!(MSG_SESSION_EXPIRED);
                }
                Refresh::Unavailable => bail!(MSG_UNAVAILABLE),
            },
            401 => {
                expire_session();
                bail!(MSG_SESSION_EXPIRED);
            }
            400 => bail!("Dienstmotor: invalid device ID"),
            _ => bail!(MSG_UNAVAILABLE),
        }
    }
    bail!(MSG_UNAVAILABLE)
}

// ---------------------------------------------------------------------------------------------
// Host side

/// Accepts a login only with a valid ticket issued for this device. A ticket is bound to the
/// first connection presenting it: later login requests on that same connection (password
/// retries, multiplexed port forwards) pass, any other connection is refused.
pub fn verify_login_ticket(ticket: &str, conn_id: i32) -> Result<(), &'static str> {
    sodiumoxide::init().ok();
    let keys: Vec<PublicKey> = branding::DM_TICKET_PUBKEYS
        .iter()
        .filter_map(|k| STANDARD.decode(k).ok())
        .filter_map(|k| PublicKey::from_slice(&k))
        .collect();
    let mut used = USED_TICKETS.lock().unwrap();
    let res = verify_ticket(ticket, &keys, &Config::get_id(), now(), conn_id, &mut used);
    if let Err(e) = res {
        log::warn!("Dienstmotor: refused login on connection {conn_id}: {e}");
        return Err(MSG_HOST_REFUSED);
    }
    Ok(())
}

fn verify_ticket(
    ticket: &str,
    keys: &[PublicKey],
    my_id: &str,
    now: i64,
    conn_id: i32,
    used: &mut HashMap<String, (i32, i64)>,
) -> Result<(), &'static str> {
    let mut parts = ticket.split('.');
    let (Some("dm1"), Some(payload), Some(sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("missing or malformed ticket");
    };
    let sig: [u8; 64] = URL_SAFE_NO_PAD
        .decode(sig)
        .ok()
        .and_then(|s| s.try_into().ok())
        .ok_or("malformed signature")?;
    let sig = Signature::from_bytes(&sig).map_err(|_| "malformed signature")?;
    let signed = &ticket[..4 + payload.len()];
    if !keys.iter().any(|k| verify_detached(&sig, signed.as_bytes(), k)) {
        return Err("bad signature");
    }
    let claims: serde_json::Value = URL_SAFE_NO_PAD
        .decode(payload)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or("malformed payload")?;
    let int = |k: &str| claims.get(k).and_then(|v| v.as_i64());
    if int("v") != Some(1)
        || str_field(&claims, "aud") != TICKET_AUDIENCE
        || str_field(&claims, "iss") != branding::AUTH_API_URL
    {
        return Err("ticket not issued for Dienstmotor Remote");
    }
    if my_id.is_empty() || str_field(&claims, "tgt") != my_id {
        return Err("ticket issued for another device");
    }
    let (Some(iat), Some(exp)) = (int("iat"), int("exp")) else {
        return Err("malformed payload");
    };
    if now > exp + HOST_CLOCK_LEEWAY || now < iat - HOST_CLOCK_LEEWAY {
        return Err("ticket expired");
    }
    let jti = str_field(&claims, "jti");
    if jti.is_empty() {
        return Err("malformed payload");
    }
    used.retain(|_, (_, until)| *until >= now);
    match used.get(&jti) {
        Some((owner, _)) if *owner != conn_id => Err("ticket already used"),
        Some(_) => Ok(()),
        None => {
            used.insert(jti, (conn_id, exp + HOST_CLOCK_LEEWAY));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::sodiumoxide::crypto::sign;

    fn make(sk: &sign::SecretKey, claims: serde_json::Value) -> String {
        let body = format!("dm1.{}", URL_SAFE_NO_PAD.encode(claims.to_string()));
        let sig = sign::sign_detached(body.as_bytes(), sk);
        format!("{body}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    fn claims(tgt: &str, iat: i64, jti: &str) -> serde_json::Value {
        serde_json::json!({
            "v": 1, "iss": branding::AUTH_API_URL, "aud": TICKET_AUDIENCE, "sub": "u",
            "usr": "alice", "tgt": tgt, "ct": "default", "jti": jti, "iat": iat, "exp": iat + 60,
        })
    }

    #[test]
    fn host_accepts_only_valid_unused_tickets_for_itself() {
        let (pk, sk) = sign::gen_keypair();
        let (_, other_sk) = sign::gen_keypair();
        let keys = [pk];
        let mut used = HashMap::new();
        let t = make(&sk, claims("123456789", 1000, "a"));
        assert_eq!(verify_ticket(&t, &keys, "123456789", 1010, 1, &mut used), Ok(()));
        // same connection (password retry) passes, another connection replaying it does not
        assert_eq!(verify_ticket(&t, &keys, "123456789", 1020, 1, &mut used), Ok(()));
        assert!(verify_ticket(&t, &keys, "123456789", 1020, 2, &mut used).is_err());
        // no ticket (official client), forged, other device, expired
        assert!(verify_ticket("", &keys, "123456789", 1010, 3, &mut used).is_err());
        let forged = make(&other_sk, claims("123456789", 1000, "b"));
        assert!(verify_ticket(&forged, &keys, "123456789", 1010, 3, &mut used).is_err());
        let other = make(&sk, claims("987654321", 1000, "c"));
        assert!(verify_ticket(&other, &keys, "123456789", 1010, 3, &mut used).is_err());
        let old = make(&sk, claims("123456789", 1000, "d"));
        assert!(verify_ticket(&old, &keys, "123456789", 1000 + 60 + HOST_CLOCK_LEEWAY + 1, 3, &mut used).is_err());
    }

    #[test]
    fn host_refuses_tampered_ticket() {
        let (pk, sk) = sign::gen_keypair();
        let t = make(&sk, claims("123456789", 1000, "a"));
        let mut c = claims("123456789", 1000, "a");
        c["tgt"] = "987654321".into();
        let swapped = format!("dm1.{}.{}", URL_SAFE_NO_PAD.encode(c.to_string()), t.rsplit('.').next().unwrap());
        assert!(verify_ticket(&swapped, &[pk], "987654321", 1010, 1, &mut HashMap::new()).is_err());
    }

    #[test]
    fn loopback_callback_requires_matching_state() {
        let req = "GET /callback?code=abc&state=s1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        assert_eq!(parse_callback(req, "s1"), Some(Ok("abc".to_owned())));
        assert!(matches!(parse_callback(req, "s2"), Some(Err(_))));
        assert_eq!(parse_callback("GET /favicon.ico HTTP/1.1\r\n\r\n", "s1"), None);
        assert_eq!(pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }
}
