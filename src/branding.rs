use base::config::keys;
use hbb_common::config;

#[cfg(any(windows, target_os = "android", target_os = "ios"))]
const APP_NAME: &str = "DienstmotorRemote";
const RENDEZVOUS_SERVER: &str = "remote.dienstmotor.com";
const RS_PUB_KEY: &str = "ZzWn4z5dLgezyx18ughykRZp8sIpOM6QsTvMB+v5WZk=";
/// Dienstmotor auth API; also the `iss` of connection tickets.
pub(crate) const AUTH_API_URL: &str = "https://remote-api.dienstmotor.com";
/// Ed25519 public keys (base64) that sign connection tickets, from
/// `auth-api/scripts/gen_ticket_key.py`. List the next key here before rotating it in.
pub(crate) const DM_TICKET_PUBKEYS: &[&str] = &["/22Mut7/CPRm+gUpNW35Knzsn0/DS8AA/m5kDTm4qQ4="];

pub fn apply() {
    // Linux packages (systemd unit, process names) and the macOS bundle path are
    // derived from the app name, so renaming there needs repackaging first.
    #[cfg(any(windows, target_os = "android", target_os = "ios"))]
    {
        *config::APP_NAME.write().unwrap() = APP_NAME.to_owned();
    }
    let mut defaults = config::DEFAULT_SETTINGS.write().unwrap();
    defaults.insert(
        keys::OPTION_CUSTOM_RENDEZVOUS_SERVER.to_owned(),
        RENDEZVOUS_SERVER.to_owned(),
    );
    defaults.insert(keys::OPTION_KEY.to_owned(), RS_PUB_KEY.to_owned());
}
